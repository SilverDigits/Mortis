using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class SetPasswordViewModel
	{
		[Required]
		[StringLength(100, ErrorMessage = "La chaîne {0} doit comporter au moins {2} caractères.", MinimumLength = 6)]
		[DataType(DataType.Password)]
		[Display(Name = "Nouveau mot de passe")]
		public string NewPassword { get; set; }

		[DataType(DataType.Password)]
		[Display(Name = "Confirmer le nouveau mot de passe")]
		[Compare("NewPassword", ErrorMessage = "Le nouveau mot de passe et le mot de passe de confirmation ne correspondent pas.")]
		public string ConfirmPassword { get; set; }
	}
}
