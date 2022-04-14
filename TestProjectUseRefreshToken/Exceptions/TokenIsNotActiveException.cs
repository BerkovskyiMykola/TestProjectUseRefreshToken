namespace TestProjectUseRefreshToken.Exceptions;

[Serializable]
public class TokenIsNotActiveException : Exception
{
    public TokenIsNotActiveException() { }

    public TokenIsNotActiveException(string message)
        : base(message) { }

    public TokenIsNotActiveException(string message, Exception inner)
        : base(message, inner) { }
}
