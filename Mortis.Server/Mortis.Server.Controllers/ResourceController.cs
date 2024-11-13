using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Mortis.Server.Models;

namespace Mortis.Server.Controllers
{
	[HostAuthentication("OpenIddict.Validation.Owin")]
	public class ResourceController : ApiController
	{
		[Authorize]
		[HttpGet]
		[Route("~/api/message")]
		public async Task<IHttpActionResult> GetMessage()
		{
			IOwinContext context = base.Request.GetOwinContext();
			ApplicationUser user = await context.GetUserManager<ApplicationUserManager>().FindByIdAsync(((ClaimsPrincipal)base.User).FindFirst("sub").Value);
			if (user == null)
			{
				context.Authentication.Challenge(new AuthenticationProperties(new Dictionary<string, string>
				{
					[".error"] = "invalid_token",
					[".error_description"] = "The specified access token is bound to an account that no longer exists."
				}), "OpenIddict.Validation.Owin");
				return Unauthorized();
			}
			return ResponseMessage(new HttpResponseMessage(HttpStatusCode.OK)
			{
				Content = (HttpContent)new StringContent(user.UserName + " has been successfully authenticated.")
			});
		}
	}
}
