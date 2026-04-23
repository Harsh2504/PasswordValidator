using System;
using System.Collections.Generic;
using System.Text;

namespace PasswordValidator.Models;
public class PasswordRuleViolation
{
    public string RuleCode { get; init; }
    public string Message { get; init; }
}
