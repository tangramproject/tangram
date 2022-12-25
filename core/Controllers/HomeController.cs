using Microsoft.AspNetCore.Mvc;

namespace TangramXtgm.Controllers;

public class HomeController : Controller
{
    /// <summary>
    /// </summary>
    /// <returns></returns>
    public IActionResult Index()
    {
        return new RedirectResult("~/swagger");
    }
}