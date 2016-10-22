//-------------------------------------------------------------------------------
// <copyright file="Password.cs" company="frokonet.ch">
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
    /// Value object for a password which acts like a string
    /// </summary>
    public class Password
    {
        private Password(string password)
        {
            this.Value = password;
        }

        private string Value { get; }

        /// <summary>
        /// Implicit operator to convert a <see cref="Password"/> into a string
        /// </summary>
        /// <param name="password">An instance of <see cref="Password"/></param>
        public static implicit operator string(Password password)
        {
            return password.Value;
        }

        /// <summary>
        /// Implicit operator to convert a string into an instance of <see cref="Password"/>
        /// </summary>
        /// <param name="password">The password as string</param>
        public static implicit operator Password(string password)
        {
            return new Password(password);
        }
    }
}