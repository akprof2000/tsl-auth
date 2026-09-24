using TslAuth.Services;

namespace TslAuth.Pages;

/// <summary>Модель _PatTable: токены, язык (админка — русский), право отзыва и обработчик/маршрут формы отзыва.</summary>
public sealed record PatTableModel(IReadOnlyList<PatDto> Items, bool Admin, bool CanRevoke, string Handler, Guid? RouteId = null);

/// <summary>Модель _SessionTable: сессии, показывать ли субъекта, можно ли отзывать (фильтр client_id сохраняется).</summary>
public sealed record SessionTableModel(IReadOnlyList<SessionDto> Items, bool ShowSubject, bool CanRevoke, string? ClientIdFilter = null);

/// <summary>Модель _RequestableRoles: роли для запроса, отмеченные в форме и уже выданные (ключи "client_id|роль").</summary>
public sealed record RequestableRolesModel(IReadOnlyList<RequestableRole> Roles, ICollection<string> Selected, ICollection<string> Assigned);
