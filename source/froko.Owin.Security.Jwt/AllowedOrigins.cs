//-------------------------------------------------------------------------------
// <copyright file="AllowedOrigins.cs" company="frokonet.ch">
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
    /// <summary>
    /// Value object for allowed origins which acts like an array of strings
    /// </summary>
    public class AllowedOrigins
    {
        /// <summary>
        /// Creates a new instance of <see cref="AllowedOrigins"/>
        /// </summary>
        /// <param name="allowedOrigins">A list of allowed origins</param>
        public AllowedOrigins(params string[] allowedOrigins)
        {
            this.Values = allowedOrigins;
        }

        private AllowedOrigins(string allowedOrigin)
        {
            this.Values = new[] { allowedOrigin };
        }

        /// <summary>
        /// Allows all origins
        /// </summary>
        public static AllowedOrigins All => new AllowedOrigins("*");

        private string[] Values { get; }

        /// <summary>
        /// Implicit operator to convert <see cref="AllowedOrigins"/> into an array of strings
        /// </summary>
        /// <param name="allowedOrigins">An instance of <see cref="AllowedOrigins"/></param>
        public static implicit operator string[](AllowedOrigins allowedOrigins)
        {
            return allowedOrigins.Values;
        }
    }
}