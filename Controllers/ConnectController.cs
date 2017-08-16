using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using dotnetcoreTokenAuthen.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
namespace dotnetcoreTokenAuthen.Controllers
{
    public class ConnectController : Controller
    {
        private readonly IOptions<IdentityOptions> _identityOptions;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public ConnectController(
            IOptions<IdentityOptions> identityOptions,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager)
        {
            _identityOptions = identityOptions;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpPost("~/connect/token"), Produces("application/json")]
        public async Task<IActionResult> Token(OpenIdConnectRequest request)
        {
            if (!request.IsPasswordGrantType())
            {
                // Return bad request if the request is not for password grant type
                return BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    ErrorDescription = "The specified grant type is not supported."
                });
            }

            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                // Return bad request if the user doesn't exist
                return BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Invalid username or password"
                });
            }

            // Check that the user can sign in and is not locked out.
            // If two-factor authentication is supported, it would also be appropriate to check that 2FA is enabled for the user
            if (!await _signInManager.CanSignInAsync(user) || (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user)))
            {
                // Return bad request is the user can't sign in
                return BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "The specified user cannot sign in."
                });
            }

            if (!await _userManager.CheckPasswordAsync(user, request.Password))
            {
                // Return bad request if the password is invalid
                return BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "Invalid username or password"
                });
            }

            // The user is now validated, so reset lockout counts, if necessary
            if (_userManager.SupportsUserLockout)
            {
                await _userManager.ResetAccessFailedCountAsync(user);
            }

            // Create the principal
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            // Claims will not be associated with specific destinations by default, so we must indicate whether they should
            // be included or not in access and identity tokens.
            foreach (var claim in principal.Claims)
            {
                // For this sample, just include all claims in all token types.
                // In reality, claims' destinations would probably differ by token type and depending on the scopes requested.
                claim.SetDestinations(OpenIdConnectConstants.Destinations.AccessToken, OpenIdConnectConstants.Destinations.IdentityToken);
            }

		
			var identity = (ClaimsIdentity)principal.Identity;
			if (string.IsNullOrEmpty(principal.FindFirstValue(OpenIdConnectConstants.Claims.Subject)))
			{
				identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Subject, await _userManager.GetUserIdAsync(user)));
			}


			// Create a new authentication ticket for the user's principal
			var ticket = new AuthenticationTicket(
                principal,
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            // Include resources and scopes, as appropriate
            var scope = new[]
            {
		        OpenIdConnectConstants.Scopes.OpenId,
		        OpenIdConnectConstants.Scopes.Email,
		        OpenIdConnectConstants.Scopes.Profile,
		        OpenIdConnectConstants.Scopes.OfflineAccess,
		        OpenIddictConstants.Scopes.Roles
		    }.Intersect(request.GetScopes());

            ticket.SetResources("http://localhost:50093/");
            ticket.SetScopes(scope);

            // Sign in the user
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

    }
}
