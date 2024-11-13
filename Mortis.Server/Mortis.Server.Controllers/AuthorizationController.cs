using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Mortis.Server.Helpers;
using Mortis.Server.Models;
using Mortis.Server.ViewModels.Authorization;
using OpenIddict.Abstractions;
using Owin;

namespace Mortis.Server.Controllers
{
	public class AuthorizationController : Controller
	{
		private readonly IOpenIddictApplicationManager _applicationManager;

		private readonly IOpenIddictAuthorizationManager _authorizationManager;

		private readonly IOpenIddictScopeManager _scopeManager;

		public AuthorizationController(IOpenIddictApplicationManager applicationManager, IOpenIddictAuthorizationManager authorizationManager, IOpenIddictScopeManager scopeManager)
		{
			_applicationManager = applicationManager;
			_authorizationManager = authorizationManager;
			_scopeManager = scopeManager;
		}

		[HttpGet]
		[Route("~/connect/authorize")]
		public async Task<ActionResult> Authorize()
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			OpenIddictRequest request = context.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
			AuthenticateResult result = await context.Authentication.AuthenticateAsync("ApplicationCookie");
			int num;
			if (result?.Identity != null)
			{
				if (request.MaxAge.HasValue && (result.Properties?.IssuedUtc.HasValue ?? false))
				{
					DateTimeOffset utcNow = DateTimeOffset.UtcNow;
					DateTimeOffset? issuedUtc = result.Properties.IssuedUtc;
					num = ((utcNow - issuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)) ? 1 : 0);
				}
				else
				{
					num = 0;
				}
			}
			else
			{
				num = 1;
			}
			if (num != 0)
			{
				context.Authentication.Challenge("ApplicationCookie");
				return new EmptyResult();
			}
			ApplicationUser user = (await context.GetUserManager<ApplicationUserManager>().FindByIdAsync(result.Identity.GetUserId())) ?? throw new InvalidOperationException("The user details cannot be retrieved.");
			object application = (await _applicationManager.FindByClientIdAsync(request.ClientId)) ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
			IOpenIddictAuthorizationManager authorizationManager = _authorizationManager;
			string id = user.Id;
			List<object> authorizations = await authorizationManager.FindAsync(id, await _applicationManager.GetIdAsync(application), "valid", "permanent", request.GetScopes()).ToListAsync();
			switch (await _applicationManager.GetConsentTypeAsync(application))
			{
			case "external":
				if (authorizations.Count == 0)
				{
					context.Authentication.Challenge(new AuthenticationProperties(new Dictionary<string, string>
					{
						[".error"] = "consent_required",
						[".error_description"] = "The logged in user is not allowed to access this client application."
					}), "OpenIddict.Server.Owin");
					return new EmptyResult();
				}
				if (authorizations.Count == 0)
				{
					break;
				}
				goto case "implicit";
			case "explicit":
				if (authorizations.Count != 0 && !request.HasPrompt("consent"))
				{
					goto case "implicit";
				}
				if (!request.HasPrompt("none"))
				{
					break;
				}
				goto IL_0b71;
			case "implicit":
			{
				ClaimsIdentity identity = new ClaimsIdentity("OpenIddict.Server.Owin", "name", "role");
				ClaimsIdentity identity2 = identity.SetClaim("sub", user.Id).SetClaim("email", user.Email).SetClaim("name", user.UserName)
					.SetClaim("preferred_username", user.UserName);
				identity2.SetClaims("role", (await context.Get<ApplicationUserManager>().GetRolesAsync(user.Id)).ToImmutableArray());
				identity.SetScopes(request.GetScopes());
				ClaimsIdentity identity3 = identity;
				identity3.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
				object authorization = authorizations.LastOrDefault();
				object obj = authorization;
				object obj2 = obj;
				if (obj2 == null)
				{
					IOpenIddictAuthorizationManager authorizationManager2 = _authorizationManager;
					ClaimsIdentity identity4 = identity;
					string id2 = user.Id;
					object obj3;
					authorization = (obj3 = await authorizationManager2.CreateAsync(identity4, id2, await _applicationManager.GetIdAsync(application), "permanent", identity.GetScopes()));
					obj2 = obj3;
				}
				_ = obj2;
				ClaimsIdentity identity5 = identity;
				identity5.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
				identity.SetDestinations(GetDestinations);
				context.Authentication.SignIn(identity);
				return new EmptyResult();
			}
			case "systematic":
				{
					if (!request.HasPrompt("none"))
					{
						break;
					}
					goto IL_0b71;
				}
				IL_0b71:
				context.Authentication.Challenge(new AuthenticationProperties(new Dictionary<string, string>
				{
					[".error"] = "consent_required",
					[".error_description"] = "Interactive user consent is required."
				}), "OpenIddict.Server.Owin");
				return new EmptyResult();
			}
			AuthorizeViewModel authorizeViewModel = new AuthorizeViewModel();
			AuthorizeViewModel authorizeViewModel2 = authorizeViewModel;
			authorizeViewModel2.ApplicationName = await _applicationManager.GetDisplayNameAsync(application);
			authorizeViewModel.Scope = request.Scope;
			authorizeViewModel.Parameters = (string.Equals(base.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase) ? (from name in base.Request.Form.AllKeys
				from value in base.Request.Form.GetValues(name)
				select new KeyValuePair<string, string>(name, value)) : (from name in base.Request.QueryString.AllKeys
				from value in base.Request.QueryString.GetValues(name)
				select new KeyValuePair<string, string>(name, value)));
			return View(authorizeViewModel);
		}

		[Authorize]
		[FormValueRequired("submit.Accept")]
		[HttpPost]
		[Route("~/connect/authorize")]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> Accept()
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			OpenIddictRequest request = context.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
			AuthenticateResult result = await context.Authentication.AuthenticateAsync("ApplicationCookie");
			if (result == null || result.Identity == null)
			{
				context.Authentication.Challenge("ApplicationCookie");
				return new EmptyResult();
			}
			ApplicationUser user = (await context.GetUserManager<ApplicationUserManager>().FindByIdAsync(result.Identity.GetUserId())) ?? throw new InvalidOperationException("The user details cannot be retrieved.");
			object application = (await _applicationManager.FindByClientIdAsync(request.ClientId)) ?? throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
			IOpenIddictAuthorizationManager authorizationManager = _authorizationManager;
			string id = user.Id;
			List<object> authorizations = await authorizationManager.FindAsync(id, await _applicationManager.GetIdAsync(application), "valid", "permanent", request.GetScopes()).ToListAsync();
			bool flag = authorizations.Count == 0;
			bool flag2 = flag;
			if (flag2)
			{
				flag2 = await _applicationManager.HasConsentTypeAsync(application, "external");
			}
			if (flag2)
			{
				context.Authentication.Challenge(new AuthenticationProperties(new Dictionary<string, string>
				{
					[".error"] = "consent_required",
					[".error_description"] = "The logged in user is not allowed to access this client application."
				}), "OpenIddict.Server.Owin");
				return new EmptyResult();
			}
			ClaimsIdentity identity = new ClaimsIdentity("OpenIddict.Server.Owin", "name", "role");
			ClaimsIdentity identity2 = identity.SetClaim("sub", user.Id).SetClaim("email", user.Email).SetClaim("name", user.UserName)
				.SetClaim("preferred_username", user.UserName);
			identity2.SetClaims("role", (await context.Get<ApplicationUserManager>().GetRolesAsync(user.Id)).ToImmutableArray());
			identity.SetScopes(request.GetScopes());
			ClaimsIdentity identity3 = identity;
			identity3.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
			object authorization = authorizations.LastOrDefault();
			object obj = authorization;
			object obj2 = obj;
			if (obj2 == null)
			{
				IOpenIddictAuthorizationManager authorizationManager2 = _authorizationManager;
				ClaimsIdentity identity4 = identity;
				string id2 = user.Id;
				object obj3;
				authorization = (obj3 = await authorizationManager2.CreateAsync(identity4, id2, await _applicationManager.GetIdAsync(application), "permanent", identity.GetScopes()));
				obj2 = obj3;
			}
			_ = obj2;
			ClaimsIdentity identity5 = identity;
			identity5.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
			identity.SetDestinations(GetDestinations);
			context.Authentication.SignIn(identity);
			return new EmptyResult();
		}

		[Authorize]
		[FormValueRequired("submit.Deny")]
		[HttpPost]
		[Route("~/connect/authorize")]
		[ValidateAntiForgeryToken]
		public ActionResult Deny()
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			context.Authentication.Challenge("OpenIddict.Server.Owin");
			return new EmptyResult();
		}

		[HttpGet]
		[Route("~/connect/logout")]
		public ActionResult Logout()
		{
			return View(new AuthorizeViewModel
			{
				Parameters = (string.Equals(base.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase) ? (from name in base.Request.Form.AllKeys
					from value in base.Request.Form.GetValues(name)
					select new KeyValuePair<string, string>(name, value)) : (from name in base.Request.QueryString.AllKeys
					from value in base.Request.QueryString.GetValues(name)
					select new KeyValuePair<string, string>(name, value)))
			});
		}

		[ActionName("Logout")]
		[HttpPost]
		[Route("~/connect/logout")]
		[ValidateAntiForgeryToken]
		public ActionResult LogoutPost()
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			context.Authentication.SignOut("ApplicationCookie");
			context.Authentication.SignOut(new AuthenticationProperties
			{
				RedirectUri = "/"
			}, "OpenIddict.Server.Owin");
			return new EmptyResult();
		}

		[HttpPost]
		[Route("~/connect/token")]
		public async Task<ActionResult> Exchange()
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			OpenIddictRequest request = context.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
			if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
			{
				AuthenticateResult result = await context.Authentication.AuthenticateAsync("OpenIddict.Server.Owin");
				ApplicationUser user = await context.GetUserManager<ApplicationUserManager>().FindByIdAsync(result.Identity.GetClaim("sub"));
				if (user == null)
				{
					context.Authentication.Challenge(new AuthenticationProperties(new Dictionary<string, string>
					{
						[".error"] = "invalid_grant",
						[".error_description"] = "The token is no longer valid."
					}), "OpenIddict.Server.Owin");
					return new EmptyResult();
				}
				if (context.GetUserManager<ApplicationUserManager>().IsLockedOut(user.Id))
				{
					context.Authentication.Challenge(new AuthenticationProperties(new Dictionary<string, string>
					{
						[".error"] = "invalid_grant",
						[".error_description"] = "The user is no longer allowed to sign in."
					}), "OpenIddict.Server.Owin");
					return new EmptyResult();
				}
				ClaimsIdentity identity = new ClaimsIdentity(result.Identity.Claims, "OpenIddict.Server.Owin", "name", "role");
				ClaimsIdentity identity2 = identity.SetClaim("sub", user.Id).SetClaim("email", user.Email).SetClaim("name", user.UserName)
					.SetClaim("preferred_username", user.UserName);
				identity2.SetClaims("role", (await context.Get<ApplicationUserManager>().GetRolesAsync(user.Id)).ToImmutableArray());
				identity.SetDestinations(GetDestinations);
				context.Authentication.SignIn(identity);
				return new EmptyResult();
			}
			throw new InvalidOperationException("The specified grant type is not supported.");
		}

		private static IEnumerable<string> GetDestinations(Claim claim)
		{
			switch (claim.Type)
			{
			case "name":
			case "preferred_username":
				yield return "access_token";
				if (claim.Subject.HasScope("profile"))
				{
					yield return "id_token";
				}
				break;
			case "email":
				yield return "access_token";
				if (claim.Subject.HasScope("email"))
				{
					yield return "id_token";
				}
				break;
			case "role":
				yield return "access_token";
				if (claim.Subject.HasScope("roles"))
				{
					yield return "id_token";
				}
				break;
			case "AspNet.Identity.SecurityStamp":
				break;
			default:
				yield return "access_token";
				break;
			}
		}
	}
}
