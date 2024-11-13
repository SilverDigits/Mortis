using System.Web.Mvc;

namespace Mortis.Server.Controllers
{
	public class HomeController : Controller
	{
		public ActionResult Index()
		{
			return View();
		}

		public ActionResult About()
		{
			base.ViewBag.Message = "Your application description page.";
			return View();
		}

		public ActionResult Contact()
		{
			base.ViewBag.Message = "Your contact page.";
			return View();
		}
	}
}
