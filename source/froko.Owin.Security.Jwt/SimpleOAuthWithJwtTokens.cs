//-------------------------------------------------------------------------------
// <copyright file="SimpleOAuthWithJwtTokens.cs" company="frokonet.ch">
//   Copyright (c) 2014-2016
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
// </copyright>
//-------------------------------------------------------------------------------

namespace froko.Owin.Security.Jwt
{
    using System.Security.Claims;
    using System.Threading.Tasks;

    /// <summary>
    /// Most simple configuration for OAuth authentication with Json Web Tokens (JWT)
    /// </summary>
    public class SimpleOAuthWithJwtTokens : OAuthWithJwtTokens
    {
        /// <summary>
        /// Allows insecure HTTP
        /// </summary>
        public override bool AllowInsecureHttp => true;

        /// <summary>
        /// Veriefies credentials by comparing username and password
        /// </summary>
        /// <param name="userName">The user name</param>
        /// <param name="password">The password</param>
        public override Task<bool> VerifyCredentials(UserName userName, Password password)
        {
            return Task.FromResult(userName == password);
        }

        /// <summary>
        /// Adds a role with the name of the user to the identity
        /// </summary>
        /// <param name="userName">The user name</param>
        /// <param name="identity">The identity</param>
        public override Task FillClaims(UserName userName, ClaimsIdentity identity)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, userName));
            return Task.CompletedTask;
        }
    }
}