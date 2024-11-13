using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Web.Mvc;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Autofac.Integration.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security.Cookies;
using Mortis.Client.Models;
using OpenIddict.Client;
using OpenIddict.Client.Owin;
using Owin;

namespace Mortis.Client
{
	public class Startup
	{
		public void Configuration(IAppBuilder app)
		{
			ServiceCollection services = new ServiceCollection();
			services.AddOpenIddict().AddCore([System.Runtime.CompilerServices.NullableContext(1)] (OpenIddictCoreBuilder options) =>
			{
				options.UseEntityFramework().UseDbContext<ApplicationDbContext>();
			}).AddClient([System.Runtime.CompilerServices.NullableContext(1)] (OpenIddictClientBuilder options) =>
			{
				options.AllowAuthorizationCodeFlow();
				options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();
				options.UseOwin().EnableRedirectionEndpointPassthrough().EnablePostLogoutRedirectionEndpointPassthrough()
					.SetCookieManager(new SystemWebCookieManager());
				options.UseSystemNetHttp().SetProductInformation(typeof(Startup).Assembly);
				options.AddRegistration(new OpenIddictClientRegistration
				{
					Issuer = new Uri("https://localhost:44349/", UriKind.Absolute),
					ProviderName = "Local",
					ProviderDisplayName = "Local OIDC server",
					ClientId = "mvc",
					ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
					Scopes = { "email", "profile" },
					RedirectUri = new Uri("callback/login/local", UriKind.Relative),
					PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative)
				});
			});
			ContainerBuilder builder = new ContainerBuilder();
			builder.Populate(services);
			builder.RegisterControllers(typeof(Startup).Assembly);
			IContainer container = builder.Build();
			app.UseAutofacLifetimeScopeInjector(container);
			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				ExpireTimeSpan = TimeSpan.FromMinutes(50.0),
				SlidingExpiration = false
			});
			app.UseMiddlewareFromContainer<OpenIddictClientOwinMiddleware>();
			DependencyResolver.SetResolver(new AutofacDependencyResolver(container));
			Task.Run(async delegate
			{
				ILifetimeScope scope = container.BeginLifetimeScope();
				try
				{
					ApplicationDbContext context = scope.Resolve<ApplicationDbContext>();
					context.Database.CreateIfNotExists();
				}
				finally
				{
					if (scope != null)
					{
						await scope.DisposeAsync();
					}
				}
			}).GetAwaiter().GetResult();
		}
	}
}
