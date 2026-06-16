"""Regression tests: SUPA-FUNC-001 exposure-aware severity.

Covers exposed RPC functions, revoked functions, safe trigger functions, and
functions with a pinned search_path.
"""

from tests._helpers import state_from_sql

from rlsguard.rules.functions import supa_func_001

_RUN_ADMIN = """
create function public.run_admin(cmd text)
returns void language plpgsql security definer
as $$ begin execute cmd; end; $$;
"""


def _only(state):
    findings = supa_func_001(state)
    assert len(findings) == 1
    return findings[0]


def test_exposed_rpc_function_is_high():
    # Reachable (EXECUTE granted to anon) + dynamic SQL + no search_path + no auth
    # check -> multiple signals -> high.
    state = state_from_sql(_RUN_ADMIN + "grant execute on function public.run_admin(text) to anon;")
    fn = state.functions[0]
    assert fn.exec_api_roles == {"anon"}

    f = _only(state)
    assert f.severity == "high"
    assert "callable function" in f.title
    assert "granted to anon" in f.explanation


def test_revoked_function_is_downgraded():
    # Same body, but EXECUTE revoked from public -> not reachable via the API ->
    # capped below the exposed equivalent.
    state = state_from_sql(_RUN_ADMIN + "revoke execute on function public.run_admin(text) from public;")
    fn = state.functions[0]
    assert fn.has_exec_grant_info is True
    assert not (fn.exec_api_roles & {"anon", "authenticated"})

    f = _only(state)
    assert f.severity == "medium"  # down from high
    assert "revoked" in f.explanation.lower()


def test_safe_trigger_function_is_low():
    state = state_from_sql(
        """
        create function public.touch_updated()
        returns trigger language plpgsql security definer set search_path = ''
        as $$ begin new.updated_at = now(); return new; end; $$;
        """
    )
    f = _only(state)
    assert f.severity == "low"
    assert "trigger function" in f.title
    assert "not exposed through the api" in f.explanation.lower()


def test_pinned_search_path_callable_is_low():
    # Reachable by default, but pinned search_path + auth check + no other signals.
    state = state_from_sql(
        """
        create function public.get_profile()
        returns setof public.profiles language sql security definer set search_path = ''
        as $$ select * from public.profiles where id = auth.uid(); $$;
        """
    )
    f = _only(state)
    assert f.severity == "low"
    assert "callable function" in f.title


def test_missing_search_path_only_is_medium_not_high():
    # A reachable callable whose ONLY risk signal is the missing search_path is
    # medium, not high (it has an auth check and no dynamic SQL / writes).
    state = state_from_sql(
        """
        create function public.get_profile()
        returns setof public.profiles language sql security definer
        as $$ select * from public.profiles where id = auth.uid(); $$;
        """
    )
    f = _only(state)
    assert f.severity == "medium"
