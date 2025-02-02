using System.Runtime.CompilerServices;
using Serilog;

namespace TangramXtgm.Extensions;

public static class LoggerExtensions
{
    public static ILogger Here(this ILogger logger,
        [CallerMemberName] string memberName = "",
        [CallerLineNumber] int sourceLineNumber = 0)
    {
        return logger
            .ForContext("MemberName", memberName)
            .ForContext("LineNumber", sourceLineNumber.ToString());
    }
}