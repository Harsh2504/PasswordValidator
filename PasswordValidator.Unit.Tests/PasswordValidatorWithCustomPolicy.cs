using System;
using System.Collections.Generic;
using System.Text;

namespace PasswordValidator.Unit.Tests
{
    public class PasswordValidatorWithCustomPolicy
    {
        public PasswordPolicy customPolicy;
        public readonly PasswordValidator _passwordValidator;
        public PasswordValidatorWithCustomPolicy()
        {
            customPolicy = new PasswordPolicy
            {
                MinimumLength = 12,
                RequireUppercase = true,
                RequireLowercase = true,
                RequireDigit = true,
                RequireSpecial = true,
                AllowSpaces = false
            };
            _passwordValidator = new PasswordValidator(customPolicy);
        }

        [Theory]
        [InlineData("Abcdefgh")]
        public void CustomPolicy_MinimumLengthIs12_ThenReturnFalse(string password)
        {
            var result = _passwordValidator.Validate(password);
            Assert.False(result.IsValid);
            Assert.Contains(result.Violations,
                v => v.RuleCode == "PASSWORD_TOO_SHORT");
        }
    }
}
