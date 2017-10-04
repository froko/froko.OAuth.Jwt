//-------------------------------------------------------------------------------
// <copyright file="JwtTokenFormat.cs" company="frokonet.ch">
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
    using System;
    using System.IdentityModel.Tokens.Jwt;

    using Microsoft.IdentityModel.Tokens;
    using Microsoft.Owin.Security;

    /// <summary>
    /// The JWT token format
    /// </summary>
    public class JwtTokenFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly string issuer;
        private readonly string audienceId;
        private readonly byte[] audienceSecret;

        /// <summary>
        /// Creates a new instance of <see cref="JwtTokenFormat"/>
        /// </summary>
        /// <param name="issuer">The issuer</param>
        /// <param name="audienceId">The audience id</param>
        /// <param name="audienceSecret">The audience secret</param>
        public JwtTokenFormat(string issuer, string audienceId, byte[] audienceSecret)
        {
            this.issuer = issuer;
            this.audienceId = audienceId;
            this.audienceSecret = audienceSecret;
        }

        /// <inheritdoc />
        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            
            var signingKey = new SymmetricSecurityKey(this.audienceSecret);
            var signingCredentials = new SigningCredentials(
                signingKey,
                SecurityAlgorithms.HmacSha256Signature);

            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;

            var handler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(
                this.issuer,
                this.audienceId,
                data.Identity.Claims,
                issued?.UtcDateTime,
                expires?.UtcDateTime,
                signingCredentials);

            return handler.WriteToken(token);
        }

        /// <inheritdoc />
        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}