using PasswordValidator.Models.Enum;
using System;
using System.Collections.Generic;
using System.Text;

namespace PasswordValidator.Models;
public class PasswordValidationResult
{
    public bool IsValid { get; init; }
    public IReadOnlyList<PasswordRuleViolation> Violations { get; init; }
    public PasswordStrength? Strength { get; init; }
}
