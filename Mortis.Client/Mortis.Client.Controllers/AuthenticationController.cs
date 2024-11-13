using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Mortis.Client.Controllers
{
	public class AuthenticationController : Controller
	{
		[HttpGet]
		[Route("~/login")]
		public ActionResult LogIn(string returnUrl)
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			AuthenticationProperties properties = new AuthenticationProperties
			{
				RedirectUri = (base.Url.IsLocalUrl(returnUrl) ? returnUrl : "/")
			};
			context.Authentication.Challenge(properties, "OpenIddict.Client.Owin");
			return new EmptyResult();
		}

		[HttpPost]
		[Route("~/logout")]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> LogOut(string returnUrl)
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			AuthenticateResult result = await context.Authentication.AuthenticateAsync("Cookies");
			if (result == null || result.Identity == null)
			{
				return Redirect(base.Url.IsLocalUrl(returnUrl) ? returnUrl : "/");
			}
			context.Authentication.SignOut("Cookies");
			AuthenticationProperties properties = new AuthenticationProperties(new Dictionary<string, string> { [".identity_token_hint"] = result.Properties.Dictionary["backchannel_id_token"] })
			{
				RedirectUri = (base.Url.IsLocalUrl(returnUrl) ? returnUrl : "/")
			};
			context.Authentication.SignOut(properties, "OpenIddict.Client.Owin");
			return Redirect(properties.RedirectUri);
		}

		[AcceptVerbs(new string[] { "GET", "POST" })]
		[Route("~/callback/login/{provider}")]
		public async Task<ActionResult> LogInCallback()
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			AuthenticateResult result = await context.Authentication.AuthenticateAsync("OpenIddict.Client.Owin");
			if (!(result.Identity?.IsAuthenticated ?? false))
			{
				throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
			}
			IEnumerable<Claim> claims = result.Identity.Claims.Where(delegate(Claim claim)
			{
				switch (claim.Type)
				{
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier":
				case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
				case "oi_reg_id":
				case "oi_prvd_name":
				case "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider":
					return true;
				default:
					return false;
				}
			});
			ClaimsIdentity identity = new ClaimsIdentity(claims, "Cookies", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role");
			AuthenticationProperties properties = new AuthenticationProperties(result.Properties.Dictionary.Where(delegate(KeyValuePair<string, string> item)
			{
				switch (item.Key)
				{
				case ".redirect":
				case "backchannel_access_token":
				case "backchannel_id_token":
				case "refresh_token":
					return true;
				default:
					return false;
				}
			}).ToDictionary((KeyValuePair<string, string> pair) => pair.Key, (KeyValuePair<string, string> pair) => pair.Value));
			context.Authentication.SignIn(properties, identity);
			return Redirect(properties.RedirectUri ?? "/");
		}

		[AcceptVerbs(new string[] { "GET", "POST" })]
		[Route("~/callback/logout/{provider}")]
		public async Task<ActionResult> LogOutCallback()
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			return Redirect((await context.Authentication.AuthenticateAsync("OpenIddict.Client.Owin")).Properties.RedirectUri);
		}
	}
}
