using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Mortis.Server.Models;

namespace Mortis.Server.Controllers
{
	[Authorize]
	public class ManageController : Controller
	{
		public enum ManageMessageId
		{
			AddPhoneSuccess,
			ChangePasswordSuccess,
			SetTwoFactorSuccess,
			SetPasswordSuccess,
			RemoveLoginSuccess,
			RemovePhoneSuccess,
			Error
		}

		private ApplicationSignInManager _signInManager;

		private ApplicationUserManager _userManager;

		private const string XsrfKey = "XsrfId";

		public ApplicationSignInManager SignInManager
		{
			get
			{
				return _signInManager ?? base.HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
			}
			private set
			{
				_signInManager = value;
			}
		}

		public ApplicationUserManager UserManager
		{
			get
			{
				return _userManager ?? base.HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
			}
			private set
			{
				_userManager = value;
			}
		}

		private IAuthenticationManager AuthenticationManager => base.HttpContext.GetOwinContext().Authentication;

		public ManageController()
		{
		}

		public ManageController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
		{
			UserManager = userManager;
			SignInManager = signInManager;
		}

		public async Task<ActionResult> Index(ManageMessageId? message)
		{
			base.ViewBag.StatusMessage = ((message == ManageMessageId.ChangePasswordSuccess) ? "Votre mot de passe a été changé." : ((message == ManageMessageId.SetPasswordSuccess) ? "Votre mot de passe a été défini." : ((message == ManageMessageId.SetTwoFactorSuccess) ? "Votre fournisseur d'authentification à 2 facteurs a été défini." : ((message == ManageMessageId.Error) ? "Une erreur s'est produite." : ((message == ManageMessageId.AddPhoneSuccess) ? "Votre numéro de téléphone a été ajouté." : ((message == ManageMessageId.RemovePhoneSuccess) ? "Votre numéro de téléphone a été supprimé." : ""))))));
			string userId = base.User.Identity.GetUserId();
			IndexViewModel indexViewModel = new IndexViewModel
			{
				HasPassword = HasPassword()
			};
			IndexViewModel indexViewModel2 = indexViewModel;
			indexViewModel2.PhoneNumber = await UserManager.GetPhoneNumberAsync(userId);
			IndexViewModel indexViewModel3 = indexViewModel;
			indexViewModel3.TwoFactor = await UserManager.GetTwoFactorEnabledAsync(userId);
			IndexViewModel indexViewModel4 = indexViewModel;
			indexViewModel4.Logins = await UserManager.GetLoginsAsync(userId);
			IndexViewModel indexViewModel5 = indexViewModel;
			indexViewModel5.BrowserRemembered = await AuthenticationManager.TwoFactorBrowserRememberedAsync(userId);
			IndexViewModel model = indexViewModel;
			return View(model);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
		{
			ManageMessageId? message;
			if ((await UserManager.RemoveLoginAsync(base.User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey))).Succeeded)
			{
				ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
				if (user != null)
				{
					await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
				}
				message = ManageMessageId.RemoveLoginSuccess;
			}
			else
			{
				message = ManageMessageId.Error;
			}
			return RedirectToAction("ManageLogins", new
			{
				Message = message
			});
		}

		public ActionResult AddPhoneNumber()
		{
			return View();
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
		{
			if (!base.ModelState.IsValid)
			{
				return View(model);
			}
			string code = await UserManager.GenerateChangePhoneNumberTokenAsync(base.User.Identity.GetUserId(), model.Number);
			if (UserManager.SmsService != null)
			{
				IdentityMessage message = new IdentityMessage
				{
					Destination = model.Number,
					Body = "Votre code de sécurité est\u00a0: " + code
				};
				await UserManager.SmsService.SendAsync(message);
			}
			return RedirectToAction("VerifyPhoneNumber", new
			{
				PhoneNumber = model.Number
			});
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> EnableTwoFactorAuthentication()
		{
			await UserManager.SetTwoFactorEnabledAsync(base.User.Identity.GetUserId(), enabled: true);
			ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
			if (user != null)
			{
				await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
			}
			return RedirectToAction("Index", "Manage");
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> DisableTwoFactorAuthentication()
		{
			await UserManager.SetTwoFactorEnabledAsync(base.User.Identity.GetUserId(), enabled: false);
			ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
			if (user != null)
			{
				await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
			}
			return RedirectToAction("Index", "Manage");
		}

		public async Task<ActionResult> VerifyPhoneNumber(string phoneNumber)
		{
			await UserManager.GenerateChangePhoneNumberTokenAsync(base.User.Identity.GetUserId(), phoneNumber);
			return (phoneNumber == null) ? View("Error") : View(new VerifyPhoneNumberViewModel
			{
				PhoneNumber = phoneNumber
			});
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
		{
			if (!base.ModelState.IsValid)
			{
				return View(model);
			}
			if ((await UserManager.ChangePhoneNumberAsync(base.User.Identity.GetUserId(), model.PhoneNumber, model.Code)).Succeeded)
			{
				ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
				if (user != null)
				{
					await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
				}
				return RedirectToAction("Index", new
				{
					Message = ManageMessageId.AddPhoneSuccess
				});
			}
			base.ModelState.AddModelError("", "La vérification du téléphone a échoué");
			return View(model);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> RemovePhoneNumber()
		{
			if (!(await UserManager.SetPhoneNumberAsync(base.User.Identity.GetUserId(), null)).Succeeded)
			{
				return RedirectToAction("Index", new
				{
					Message = ManageMessageId.Error
				});
			}
			ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
			if (user != null)
			{
				await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
			}
			return RedirectToAction("Index", new
			{
				Message = ManageMessageId.RemovePhoneSuccess
			});
		}

		public ActionResult ChangePassword()
		{
			return View();
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> ChangePassword(ChangePasswordViewModel model)
		{
			if (!base.ModelState.IsValid)
			{
				return View(model);
			}
			IdentityResult result = await UserManager.ChangePasswordAsync(base.User.Identity.GetUserId(), model.OldPassword, model.NewPassword);
			if (result.Succeeded)
			{
				ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
				if (user != null)
				{
					await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
				}
				return RedirectToAction("Index", new
				{
					Message = ManageMessageId.ChangePasswordSuccess
				});
			}
			AddErrors(result);
			return View(model);
		}

		public ActionResult SetPassword()
		{
			return View();
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<ActionResult> SetPassword(SetPasswordViewModel model)
		{
			if (base.ModelState.IsValid)
			{
				IdentityResult result = await UserManager.AddPasswordAsync(base.User.Identity.GetUserId(), model.NewPassword);
				if (result.Succeeded)
				{
					ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
					if (user != null)
					{
						await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
					}
					return RedirectToAction("Index", new
					{
						Message = ManageMessageId.SetPasswordSuccess
					});
				}
				AddErrors(result);
			}
			return View(model);
		}

		public async Task<ActionResult> ManageLogins(ManageMessageId? message)
		{
			base.ViewBag.StatusMessage = ((message == ManageMessageId.RemoveLoginSuccess) ? "La connexion externe a été supprimée." : ((message == ManageMessageId.Error) ? "Une erreur s'est produite." : ""));
			ApplicationUser user = await UserManager.FindByIdAsync(base.User.Identity.GetUserId());
			if (user == null)
			{
				return View("Error");
			}
			IList<UserLoginInfo> userLogins = await UserManager.GetLoginsAsync(base.User.Identity.GetUserId());
			List<AuthenticationDescription> otherLogins = (from auth in AuthenticationManager.GetExternalAuthenticationTypes()
				where userLogins.All((UserLoginInfo ul) => auth.AuthenticationType != ul.LoginProvider)
				select auth).ToList();
			base.ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;
			return View(new ManageLoginsViewModel
			{
				CurrentLogins = userLogins,
				OtherLogins = otherLogins
			});
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public ActionResult LinkLogin(string provider)
		{
			return new AccountController.ChallengeResult(provider, base.Url.Action("LinkLoginCallback", "Manage"), base.User.Identity.GetUserId());
		}

		public async Task<ActionResult> LinkLoginCallback()
		{
			ExternalLoginInfo loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync("XsrfId", base.User.Identity.GetUserId());
			if (loginInfo == null)
			{
				return RedirectToAction("ManageLogins", new
				{
					Message = ManageMessageId.Error
				});
			}
			return (await UserManager.AddLoginAsync(base.User.Identity.GetUserId(), loginInfo.Login)).Succeeded ? RedirectToAction("ManageLogins") : RedirectToAction("ManageLogins", new
			{
				Message = ManageMessageId.Error
			});
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing && _userManager != null)
			{
				_userManager.Dispose();
				_userManager = null;
			}
			base.Dispose(disposing);
		}

		private void AddErrors(IdentityResult result)
		{
			foreach (string error in result.Errors)
			{
				base.ModelState.AddModelError("", error);
			}
		}

		private bool HasPassword()
		{
			ApplicationUser user = UserManager.FindById(base.User.Identity.GetUserId());
			if (user != null)
			{
				return user.PasswordHash != null;
			}
			return false;
		}

		private bool HasPhoneNumber()
		{
			ApplicationUser user = UserManager.FindById(base.User.Identity.GetUserId());
			if (user != null)
			{
				return user.PhoneNumber != null;
			}
			return false;
		}
	}
}
