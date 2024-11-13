using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class AddPhoneNumberViewModel
	{
		[Required]
		[Phone]
		[Display(Name = "Numéro de téléphone")]
		public string Number { get; set; }
	}
}
