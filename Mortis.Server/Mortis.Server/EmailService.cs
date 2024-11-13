using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace Mortis.Server
{
	public class EmailService : IIdentityMessageService
	{
		public Task SendAsync(IdentityMessage message)
		{
			return Task.FromResult(0);
		}
	}
}
