using System;
using System.Threading;
using System.Threading.Tasks;

namespace TangramXtgm.Helper;

/// <summary>
/// 
/// </summary>
public static class AsyncHelper
{
    private static readonly TaskFactory MyTaskFactory = new(CancellationToken.None,
        TaskCreationOptions.None,
        TaskContinuationOptions.None,
        TaskScheduler.Default);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="func"></param>
    /// <typeparam name="TResult"></typeparam>
    /// <returns></returns>
    public static TResult RunSync<TResult>(Func<Task<TResult>> func)
    {
        return MyTaskFactory
            .StartNew(func)
            .Unwrap()
            .GetAwaiter()
            .GetResult();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="func"></param>
    public static void RunSync(Func<Task> func)
    {
        MyTaskFactory
            .StartNew<Task>(func)
            .Unwrap()
            .GetAwaiter()
            .GetResult();
    }
    
    /// <summary>
    /// 
    /// </summary>
    /// <param name="workItem"></param>
    public static void Invoke(Func<Task> workItem)
    {
         workItem.Invoke();
    }
}