using TslAuth.Services;

namespace TslAuth.Api;

/// <summary>Общий фильтр групп API: ошибки бизнес-логики (<see cref="AdminException"/>) → ProblemDetails с их кодом.</summary>
public static class ApiErrors
{
    public static async ValueTask<object?> Handle(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (AdminException ex)
        {
            return Results.Problem(detail: ex.Message, statusCode: ex.StatusCode);
        }
    }
}
