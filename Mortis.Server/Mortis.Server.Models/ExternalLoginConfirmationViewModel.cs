using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class ExternalLoginConfirmationViewModel
	{
		[Required]
		[Display(Name = "Courrier électronique")]
		public string Email { get; set; }
	}
}
