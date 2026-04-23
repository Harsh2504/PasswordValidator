using PasswordValidator.Models.Enum;

namespace PasswordValidator.Unit.Tests;

public class PasswordValidatorTests
{
    private readonly PasswordValidator _passwordValidator;


    public PasswordValidatorTests()
    {
        _passwordValidator = new PasswordValidator();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Validate_WhenPasswordIsNullOrWhitespace_ThenReturnFalse(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.False(result.IsValid);
        Assert.Contains(result.Violations,
            v => v.RuleCode == "PASSWORD_NULL_OR_WHITESPACE");
    }

    [Theory]
    [InlineData("Abc123")]
    public void Validate_WhenPasswordLengthIsLessThan8_ThenReturnFalse(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.False(result.IsValid);
        Assert.Contains(result.Violations,
            v => v.RuleCode == "PASSWORD_TOO_SHORT");
    }

    [Theory]
    [InlineData("ascabcasc")]
    public void Validate_WhenPasswordNotContainsUppercaseLetter_ThenReturnFalse(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.False(result.IsValid);

        Assert.Contains(result.Violations,
            v => v.RuleCode == "MISSING_UPPERCASE_LETTER");
    }

    [Theory]
    [InlineData("ASKCJBAELSJ")]
    public void Validate_WhenPasswordNotContainsLowercaseLetter_ThenReturnFalse(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.False(result.IsValid);
        Assert.Contains(result.Violations,
            v => v.RuleCode == "MISSING_LOWERCASE_LETTER");
    }

    [Theory]
    [InlineData("Abcdefghs")]
    public void Validate_WhenPasswordNotContainsDigit_ThenReturnFalse(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.False(result.IsValid);
        Assert.Contains(result.Violations,
            v => v.RuleCode == "MISSING_DIGIT");
    }

    [Theory]
    [InlineData("Abcdefgh1")]
    public void Validate_WhenPasswordNotContainsSpecialCharacter_ThenReturnFalse(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.False(result.IsValid);
        Assert.Contains(result.Violations,
            v => v.RuleCode == "MISSING_SPECIAL_CHARACTER");
    }

    [Theory]
    [InlineData("Abcdefgh1  !")]
    public void Validate_WhenPasswordHasSpacings_ThenReturnFalse(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.False(result.IsValid);
        Assert.Contains(result.Violations,
            v => v.RuleCode == "PASSWORD_CONTAINS_SPACING");
    }

    [Theory]
    [InlineData("Password@1234")]
    public void Validate_WhenPasswordIsValid_ThenReturnTrue(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.True(result.IsValid);
        Assert.Empty(result.Violations);
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("AB")]
    [InlineData("123")]
    [InlineData("!@#")]
    [InlineData("abcdeafghi")]
    public void Validate_WhenPasswordIsWeak_ThenReturnStrengthWeak(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.Equal(PasswordStrength.Weak, result.Strength);
    }

    [Theory]
    [InlineData("Abcdefgh")]
    [InlineData("Abcdefg1")]
    [InlineData("Abcdefg!")]
    public void Validate_WhenPasswordIsMedium_ThenReturnStrengthMedium(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.Equal(PasswordStrength.Medium, result.Strength);
    }

    [Theory]
    [InlineData("Password@1234")]
    [InlineData("Str0ngP@ssw0rd!")]
    public void Validate_WhenPasswordIsStrong_ThenReturnStrengthStrong(string password)
    {
        var result = _passwordValidator.Validate(password);
        Assert.Equal(PasswordStrength.Strong, result.Strength);
    }
}
