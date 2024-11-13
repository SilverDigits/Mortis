using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class VerifyCodeViewModel
	{
		[Required]
		public string Provider { get; set; }

		[Required]
		[Display(Name = "Code")]
		public string Code { get; set; }

		public string ReturnUrl { get; set; }

		[Display(Name = "Mémoriser ce navigateur\u00a0?")]
		public bool RememberBrowser { get; set; }

		public bool RememberMe { get; set; }
	}
}
