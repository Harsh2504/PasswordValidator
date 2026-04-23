using PasswordValidator.Models;
using PasswordValidator.Models.Enum;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace PasswordValidator;

public class PasswordValidator
{
    private readonly List<PasswordRuleViolation> violations = new List<PasswordRuleViolation>();

    public PasswordValidationResult Validate(string password)
    {
        if (CheckNullOrWhitespace(password, violations) || CheckPasswordSpaces(password, violations))
        {
            return new PasswordValidationResult
            {
                IsValid = false,
                Violations = violations
            };
        }
        CheckLength(password, violations);

        CheckUppercaseLetter(password, violations);
        CheckLowercaseLetter(password, violations);
        CheckDigit(password, violations);
        CheckSpecialCharacter(password, violations);

        return new PasswordValidationResult
        {
            IsValid = violations.Count == 0,
            Violations = violations,
            Strength = violations.Count switch
            {
                0 => PasswordStrength.Strong,
                1 => PasswordStrength.Medium,
                2 => PasswordStrength.Medium,
                _ => PasswordStrength.Weak
            }

        };
    }

    private bool CheckNullOrWhitespace(string password, List<PasswordRuleViolation> violations)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            violations.Add(new PasswordRuleViolation
            {
                RuleCode = "PASSWORD_NULL_OR_WHITESPACE",
                Message = "Password cannot be null, empty, or whitespace."
            });
            return true;
        }
        return false;
    }

    private void CheckLength(string password, List<PasswordRuleViolation> violations)
    {
        if (password.Length < 8)
        {
            violations.Add(new PasswordRuleViolation
            {
                RuleCode = "PASSWORD_TOO_SHORT",
                Message = "Password must be at least 8 characters long."
            });
        }
    }

    private void CheckUppercaseLetter(string password, List<PasswordRuleViolation> violations)
    {
        if (!password.Any(char.IsUpper))
        {
            violations.Add(new PasswordRuleViolation
            {
                RuleCode = "MISSING_UPPERCASE_LETTER",
                Message = "Password must contain at least one uppercase letter."
            });
        }
    }

    private void CheckLowercaseLetter(string password, List<PasswordRuleViolation> violations)
    {
        if (!password.Any(char.IsLower))
        {
            violations.Add(new PasswordRuleViolation
            {
                RuleCode = "MISSING_LOWERCASE_LETTER",
                Message = "Password must contain at least one lowercase letter."
            });
        }
    }

    private void CheckDigit(string password, List<PasswordRuleViolation> violations)
    {
        if (!password.Any(char.IsDigit))
        {
            violations.Add(new PasswordRuleViolation
            {
                RuleCode = "MISSING_DIGIT",
                Message = "Password must contain at least one digit."
            });
        }
    }

    private void CheckSpecialCharacter(string password, List<PasswordRuleViolation> violations)
    {
        var regex = @"[!@#$%^&*\(\)\-_+=\{\}\[\]:;""'<>,\.?/\\|~]";

        if (!Regex.IsMatch(password, regex))
        {
            violations.Add(new PasswordRuleViolation
            {
                RuleCode = "MISSING_SPECIAL_CHARACTER",
                Message = "Password must contain at least one special character."
            });
        }
    }
    private bool CheckPasswordSpaces(string password, List<PasswordRuleViolation> violations)
    {

        if (password.Any(char.IsWhiteSpace))
        {
            violations.Add(new PasswordRuleViolation
            {
                RuleCode = "PASSWORD_CONTAINS_SPACING",
                Message = "Password cannot contain spaces."
            });
            return true;
        }
        return false;
    }
}
