using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class VerifyPhoneNumberViewModel
	{
		[Required]
		[Display(Name = "Code")]
		public string Code { get; set; }

		[Required]
		[Phone]
		[Display(Name = "Numéro de téléphone")]
		public string PhoneNumber { get; set; }
	}
}
