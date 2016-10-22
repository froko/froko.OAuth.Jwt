//-------------------------------------------------------------------------------
// <copyright file="UserName.cs" company="frokonet.ch">
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
    /// Value object for a user name which acts like a string
    /// </summary>
    public class UserName
    {
        private UserName(string userName)
        {
            this.Value = userName;
        }

        private string Value { get; }

        /// <summary>
        /// Implicit operator to convert a <see cref="UserName"/> into a string
        /// </summary>
        /// <param name="username">An instance of <see cref="UserName"/></param>
        public static implicit operator string(UserName username)
        {
            return username.Value;
        }

        /// <summary>
        /// Implicit operator to convert a string into an instance of <see cref="UserName"/>
        /// </summary>
        /// <param name="userName">The user name as string</param>
        public static implicit operator UserName(string userName)
        {
            return new UserName(userName);
        }
    }
}