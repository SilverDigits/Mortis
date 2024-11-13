using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class ForgotPasswordViewModel
	{
		[Required]
		[EmailAddress]
		[Display(Name = "E-mail")]
		public string Email { get; set; }
	}
}
