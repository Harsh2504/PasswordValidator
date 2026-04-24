namespace PasswordValidator
{
    public class PasswordPolicy
    {
        public int MinimumLength { get; init; } = 8;
        public bool RequireUppercase { get; init; } = true;
        public bool RequireLowercase { get; init; } = true;
        public bool RequireDigit { get; init; } = true;
        public bool RequireSpecial { get; init; } = true;
        public bool AllowSpaces { get; init; } = false;
    }
}
