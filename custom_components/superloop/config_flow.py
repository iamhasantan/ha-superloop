import asyncio
import logging
import aiohttp
import async_timeout
import voluptuous as vol
import time

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import BASE_API_URL
from .token_utils import jwt_expiry_ms, strip_bearer_prefix

_LOGGER = logging.getLogger(__name__)

DOMAIN = "superloop"

# New preferred endpoint (legacy JWT login, no MFA, long TTL)
LOGIN_JWT_URL = "https://webservices-api.superloop.com/v1/login-jwt"

# Old endpoints (kept as fallback)
LOGIN_URL = "https://webservices.myexetel.exetel.com.au/api/auth/token"
MFA_URL = "https://webservices-api.superloop.com/v1/mfa"
CREATE_MFA_URL = "https://webservices-api.superloop.com/v1/create-mfa"
VERIFY_MFA_URL = "https://webservices-api.superloop.com/v1/verify-mfa"

class SuperloopConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Superloop."""

    VERSION = 1

    def __init__(self):
        self._reauth_entry = None
        self._email = None
        self._password = None
        self._access_token = None
        self._refresh_token = None
        self._expires_in = None
        self._expires_at_ms = None
        self._user_id = None
        self._brand = None
        self._mfa_method = "MfaOverSMS"

    async def async_step_user(self, user_input=None):
        """Choose a login method without assuming every customer has a password."""
        if user_input is not None:
            if user_input["auth_method"] == "existing_token":
                return await self.async_step_existing_token()
            return await self.async_step_password()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("auth_method", default="existing_token"): vol.In({
                    "existing_token": "Existing access token (experimental)",
                    "legacy_password": "Email and password (legacy)",
                }),
            }),
        )

    async def async_step_existing_token(self, user_input=None):
        """Validate an existing token against the original account API.

        This is a diagnostic workaround, NOT an implementation of Superloop's
        currently undocumented email/postcode/OTP authentication protocol.
        """
        errors = {}
        if user_input is not None:
            email = user_input["email"].strip().lower()
            token = strip_bearer_prefix(user_input["access_token"])
            exp_ms = jwt_expiry_ms(token)
            if not email or not token or (exp_ms is not None and exp_ms <= int(time.time() * 1000)):
                errors["base"] = "invalid_auth"
            else:
                try:
                    session = async_get_clientsession(self.hass)
                    async with async_timeout.timeout(15):
                        async with session.get(
                            f"{BASE_API_URL}/getServices/",
                            headers={"Authorization": f"Bearer {token}"},
                            allow_redirects=False,
                        ) as response:
                            if response.status in (401, 403):
                                errors["base"] = "invalid_auth"
                            elif response.status != 200:
                                errors["base"] = "incompatible_api"
                            else:
                                try:
                                    services = await response.json()
                                except (ValueError, aiohttp.ContentTypeError):
                                    errors["base"] = "incompatible_api"
                                else:
                                    if not isinstance(services, (dict, list)):
                                        errors["base"] = "incompatible_api"
                except (asyncio.TimeoutError, aiohttp.ClientError):
                    errors["base"] = "cannot_connect"
                except Exception:
                    _LOGGER.exception("Unexpected error validating Superloop access token")
                    errors["base"] = "unknown"

                if not errors:
                    # Never store an OTP, postcode or password. Token stays in HA's
                    # protected config-entry storage, not in logs or Git.
                    data = {
                        "email": email,
                        "access_token": token,
                        "refresh_token": None,
                        "expires_at_ms": exp_ms,
                        "login_method": "external_token",
                    }
                    if self._reauth_entry:
                        self.hass.config_entries.async_update_entry(
                            self._reauth_entry,
                            data={**self._reauth_entry.data, **data},
                        )
                        await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
                        return self.async_abort(reason="reauth_successful")
                    return self.async_create_entry(title=email, data=data)

        return self.async_show_form(
            step_id="existing_token",
            data_schema=vol.Schema({
                vol.Required("email", default=self._email or ""): str,
                vol.Required("access_token"): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD),
                ),
            }),
            errors=errors,
        )

    async def async_step_password(self, user_input=None):
        _LOGGER.debug("Starting user setup step")
        if user_input is not None:
            self._email = user_input["email"]
            self._password = user_input["password"]
            mfa_method = user_input.get("mfa_method", "sms")
            self._mfa_method = {"sms": "MfaOverSMS", "email": "MfaOverEmail"}.get(mfa_method, "MfaOverSMS")

            # 1) Try the legacy JWT login first (preferred: no MFA, long TTL)
            try:
                _LOGGER.debug("Attempting login-jwt for %s", self._email)
                jwt_data = await self._attempt_login_jwt(self._email, self._password)
                self._access_token = jwt_data["access_token"]
                self._expires_in = int(jwt_data.get("expires_in", 0)) or 31536000
                self._expires_at_ms = int(time.time() * 1000) + self._expires_in * 1000
                self._user_id = jwt_data.get("user_id")
                self._brand = jwt_data.get("brand")

                _LOGGER.debug("login-jwt successful; expires_in=%s (~%0.1f days)",
                              self._expires_in, self._expires_in / 86400)

                # Reauth update path
                if self._reauth_entry:
                    self.hass.config_entries.async_update_entry(
                        self._reauth_entry,
                        data={
                            **self._reauth_entry.data,
                            "email": self._email,
                            "access_token": self._access_token,
                            "expires_in": self._expires_in,
                            "expires_at_ms": self._expires_at_ms,
                            "user_id": self._user_id,
                            "brand": self._brand,
                            "login_method": "login_jwt",
                        },
                    )
                    await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
                    return self.async_abort(reason="reauth_successful")

                # Initial create
                return self.async_create_entry(
                    title=self._email,
                    data={
                        "email": self._email,
                        "access_token": self._access_token,
                        "expires_in": self._expires_in,
                        "expires_at_ms": self._expires_at_ms,
                        "user_id": self._user_id,
                        "brand": self._brand,
                        "login_method": "login_jwt",
                    },
                )

            except InvalidAuth:
                # If login-jwt rejects credentials, show invalid_auth
                return self.async_show_form(step_id="user", errors={"base": "invalid_auth"})
            except CannotConnect:
                return self.async_show_form(step_id="user", errors={"base": "cannot_connect"})
            except Exception as ex:
                _LOGGER.exception("login-jwt failed unexpectedly, falling back to standard login + MFA: %s", ex)

            # 2) Fallback to old login + MFA if login-jwt didn't work
            try:
                self._access_token, self._refresh_token, self._expires_in = await self._attempt_login(self._email, self._password)
                _LOGGER.debug("Legacy login successful; triggering MFA")
                await self._trigger_mfa(self._access_token, self._mfa_method)
            except InvalidAuth:
                return self.async_show_form(step_id="user", errors={"base": "invalid_auth"})
            except CannotConnect:
                return self.async_show_form(step_id="user", errors={"base": "cannot_connect"})
            except Exception as ex:
                _LOGGER.exception("Unexpected error during legacy login: %s", ex)
                return self.async_show_form(step_id="user", errors={"base": "unknown"})

            return await self.async_step_2fa()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("email"): str,
                vol.Required("password"): str,
                vol.Required("mfa_method", default="sms"): vol.In({
                    "sms": "SMS (Text Message)",
                    "email": "Email",
                }),
            }),
        )

    async def async_step_2fa(self, user_input=None):
        """Only used when falling back to legacy login flow."""
        if user_input is not None:
            code = user_input["code"]
            try:
                await self._verify_2fa_code(self._access_token, code, self._mfa_method)
            except InvalidAuth:
                return self.async_show_form(step_id="2fa", errors={"base": "invalid_2fa"})
            except Exception as ex:
                _LOGGER.exception("Unexpected error during 2FA verification: %s", str(ex))
                return self.async_show_form(step_id="2fa", errors={"base": "unknown"})

            if self._reauth_entry:
                self.hass.config_entries.async_update_entry(
                    self._reauth_entry,
                    data={
                        **self._reauth_entry.data,
                        "access_token": self._access_token,
                        "refresh_token": self._refresh_token,
                        "expires_in": self._expires_in,
                        "login_method": "legacy_auth",
                    },
                )
                await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
                return self.async_abort(reason="reauth_successful")

            return self.async_create_entry(
                title=self._email,
                data={
                    "email": self._email,
                    "access_token": self._access_token,
                    "refresh_token": self._refresh_token,
                    "expires_in": self._expires_in,
                    "login_method": "legacy_auth",
                },
            )

        return self.async_show_form(
            step_id="2fa",
            data_schema=vol.Schema({ vol.Required("code"): str }),
        )

    async def async_step_reauth(self, entry_data):
        self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        self._email = self._reauth_entry.title
        return await self.async_step_user()

    # ---------- New preferred login (no MFA) ----------
    async def _attempt_login_jwt(self, email: str, password: str):
        payload = {
            "username": email,
            "password": password,
            "persistLogin": True,
            "brand": "superloop",
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with async_timeout.timeout(15):
                    resp = await session.post(LOGIN_JWT_URL, json=payload)
                    if resp.status == 401:
                        raise InvalidAuth()
                    if resp.status != 200:
                        text = await resp.text()
                        _LOGGER.error("login-jwt failed HTTP %s: %s", resp.status, text[:200])
                        raise CannotConnect()
                    data = await resp.json()
                    # Expect: access_token, expires_in (~31536000), user_id, brand, ignore_mfa
                    if "access_token" not in data:
                        raise InvalidAuth()
                    return data
        except asyncio.TimeoutError:
            raise CannotConnect()
        except InvalidAuth:
            raise
        except Exception as ex:
            _LOGGER.exception("Unexpected login-jwt error: %s", ex)
            raise

    # ---------- Legacy login + MFA (fallback) ----------
    async def _attempt_login(self, email: str, password: str):
        payload = {
            "username": email,
            "password": password,
            "persistLogin": True,
            "brand": "superloop",
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with async_timeout.timeout(10):
                    response = await session.post(LOGIN_URL, json=payload)
                    if response.status != 200:
                        raise InvalidAuth()
                    data = await response.json()
                    return data["access_token"], data["refresh_token"], data.get("expires_in", 14400)
        except asyncio.TimeoutError:
            raise CannotConnect()
        except Exception as ex:
            _LOGGER.exception("Unexpected error during legacy login: %s", str(ex))
            raise

    async def _trigger_mfa(self, access_token: str, mfa_action: str):
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            async with aiohttp.ClientSession() as session:
                async with async_timeout.timeout(10):
                    await session.get(MFA_URL, headers=headers)
                    await session.post(CREATE_MFA_URL, json={"action": mfa_action}, headers=headers)
        except asyncio.TimeoutError:
            raise CannotConnect()
        except Exception as ex:
            _LOGGER.exception("Unexpected error during MFA triggering: %s", str(ex))
            raise

    async def _verify_2fa_code(self, access_token: str, code: str, mfa_action: str):
        headers = {"Authorization": f"Bearer {access_token}"}
        payload = {"action": mfa_action, "token": code}
        try:
            async with aiohttp.ClientSession() as session:
                async with async_timeout.timeout(10):
                    response = await session.post(VERIFY_MFA_URL, json=payload, headers=headers)
                    if response.status != 200:
                        raise InvalidAuth()
        except asyncio.TimeoutError:
            raise CannotConnect()
        except Exception as ex:
            _LOGGER.exception("Unexpected error during 2FA verification: %s", str(ex))
            raise

class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate invalid authentication."""
