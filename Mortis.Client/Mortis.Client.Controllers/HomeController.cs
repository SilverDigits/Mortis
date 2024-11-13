using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;

namespace Mortis.Client.Controllers
{
	public class HomeController : Controller
	{
		private readonly IHttpClientFactory _httpClientFactory;

		public HomeController(IHttpClientFactory httpClientFactory)
		{
			_httpClientFactory = httpClientFactory;
		}

		[HttpGet]
		[Route("~/")]
		public ActionResult Index()
		{
			return View();
		}

		[Authorize]
		[HttpPost]
		[Route("~/")]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> Index(CancellationToken cancellationToken)
		{
			IOwinContext context = base.HttpContext.GetOwinContext();
			string token = (await context.Authentication.AuthenticateAsync("Cookies")).Properties.Dictionary["backchannel_access_token"];
			HttpClient client = _httpClientFactory.CreateClient();
			try
			{
				HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44349/api/message");
				try
				{
					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
					HttpResponseMessage response = await ((HttpMessageInvoker)client).SendAsync(request, cancellationToken);
					try
					{
						response.EnsureSuccessStatusCode();
						return View((object)(await response.Content.ReadAsStringAsync()));
					}
					finally
					{
						((IDisposable)response)?.Dispose();
					}
				}
				finally
				{
					((IDisposable)request)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)client)?.Dispose();
			}
		}
	}
}
