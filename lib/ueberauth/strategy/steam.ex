defmodule Ueberauth.Strategy.Steam do
  @moduledoc ~S"""
  Steam OpenID for Überauth.
  """

  use Ueberauth.Strategy

  require Logger

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Extra

  @doc ~S"""
  Handles initial request for Steam authentication.

  Redirects the given `conn` to the Steam login page.
  """
  @spec handle_request!(Plug.Conn.t) :: Plug.Conn.t
  def handle_request!(conn) do
    # Ensure session is fetched and we store a server side 'state' token
    # in the session for round-tripping. We try to prefer the CSRF state
    # if the session stores a valid CSRF token, but fall back to a newly
    # generated token when necessary.
    conn =
      try do
        Plug.Conn.fetch_session(conn)
      rescue
        _ in ArgumentError ->
          conn
      end

    state =
      try do
        session_token = Plug.Conn.get_session(conn, "_csrf_token")

        state_from_session = if is_binary(session_token), do: Plug.CSRFProtection.dump_state_from_session(session_token), else: nil

        if state_from_session do
          state_from_session
        else
          # Generate a url-safe state value ~24 chars (matches Plug encoding sizes)
          :crypto.strong_rand_bytes(18) |> Base.url_encode64(padding: false)
        end
      rescue
        _ in ArgumentError ->
          :crypto.strong_rand_bytes(18) |> Base.url_encode64(padding: false)
      end

    conn =
      try do
        conn
        |> Plug.Conn.put_session("ueberauth_steam_state", state)
        |> Plug.Conn.put_resp_cookie("ueberauth.state_param", state, http_only: true, max_age: 300, same_site: "Lax")
      rescue
        _ in ArgumentError -> conn
      end

    query =
      %{
        "openid.mode" => "checkid_setup",
        "openid.realm" => callback_url(conn),
        "openid.return_to" => callback_url(conn, state: state),
        "openid.ns" => "http://specs.openid.net/auth/2.0",
        "openid.claimed_id" => "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.identity" => "http://specs.openid.net/auth/2.0/identifier_select",
      }
      |> URI.encode_query

    redirect!(conn, "https://steamcommunity.com/openid/login?" <> query)
  end

  @doc ~S"""
  Handles the callback from Steam.
  """
  @spec handle_callback!(Plug.Conn.t) :: Plug.Conn.t
  def handle_callback!(conn = %Plug.Conn{params: %{"openid.mode" => "id_res"}}) do
    # If a server-side state token was stored in the session during the
    # request phase, validate that it is present and matches the returned
    # params. If session state exists but the returned state is missing or
    # does not match, treat as a CSRF attack.
    conn =
      try do
        Plug.Conn.fetch_session(conn)
      rescue
        _ in ArgumentError ->
          conn
      end

    {conn, failed} =
      try do

        session_state =
          try do
            Plug.Conn.get_session(conn, "ueberauth_steam_state")
          rescue
            _ in ArgumentError -> nil
          end

        # prefer req_cookies if already present (eg. in tests via put_req_cookie).
        headers = Plug.Conn.get_req_header(conn, "cookie")
        Logger.debug("[ueberauth_steam] req_cookies=#{inspect(conn.req_cookies)} cookies=#{inspect(conn.cookies)} headers=#{inspect(headers)}")
        cookie_state = Map.get(conn.req_cookies || %{}, "ueberauth.state_param") || Map.get(conn.cookies || %{}, "ueberauth.state_param")

        # fallback: parse cookie header string manually if req_cookies/cookies not present
        cookie_state =
          if cookie_state == nil do
            case Plug.Conn.get_req_header(conn, "cookie") do
              [cookie_header | _] when is_binary(cookie_header) ->
                cookie_header
                |> String.split(";")
                |> Enum.map(&String.trim/1)
                |> Enum.find_value(fn part ->
                  case String.split(part, "=", parts: 2) do
                    ["ueberauth.state_param", value] -> value
                    _ -> nil
                  end
                end)
              _ ->
                nil
            end
          else
            cookie_state
          end

        # also look for a CSRF-derived state candidate if present
        csrf_candidate =
          try do
            case Plug.Conn.get_session(conn, "_csrf_token") do
              nil -> nil
              s when is_binary(s) -> Plug.CSRFProtection.dump_state_from_session(s)
            end
          rescue
            _ in ArgumentError -> nil
          end

        candidates = Enum.filter([session_state, cookie_state, csrf_candidate], &(&1 != nil))

        returned = conn.params["state"]
        require Logger
        Logger.debug("[ueberauth_steam] state validation: candidates=#{inspect(candidates)} returned=#{inspect(returned)}")

        cond do
          candidates == [] ->
            # no state was stored/expected — allow the flow; DO NOT set errors
            {conn, false}

          returned == nil ->
            Logger.debug("[ueberauth_steam] state validation -> missing returned state, setting csrf failure")
            {set_errors!(conn, [error("csrf_attack", "Cross-Site Request Forgery attack")]), true}

          not Enum.member?(candidates, returned) ->
            Logger.debug("[ueberauth_steam] state validation -> returned state does not match candidates=#{inspect(candidates)} returned=#{inspect(returned)}")
            {set_errors!(conn, [error("csrf_attack", "Cross-Site Request Forgery attack")]), true}

          true ->
              # valid: clear persisted states (safe in tests/apps without session/cookies)
              conn =
                try do
                  Plug.Conn.delete_session(conn, "ueberauth_steam_state")
                rescue
                  _ in ArgumentError -> conn
                end

              try do
                Plug.Conn.delete_resp_cookie(conn, "ueberauth.state_param")
              rescue
                _ in ArgumentError -> conn
              end

            {conn, false}
        end
      rescue
        _ -> {conn, false}
      end

    # if failed we must immediately return to avoid overwriting failure
    if failed do
      conn
    else

    require Logger
    Logger.debug("[ueberauth_steam] after state validation, failure=#{inspect(conn.assigns[:ueberauth_failure])}")

    # If we've already set an ueberauth failure (e.g. CSRF attack detected)
    # return early so we don't attempt to validate the openid or make HTTP
    # calls.
    if conn.assigns[:ueberauth_failure] do
      conn
    else
      Logger.debug("[ueberauth_steam] proceeding to user validation; params=#{inspect(conn.params)}")
      params = conn.params

      [valid, user] =
      [ # Validate and retrieve the steam user at the same time.
        fn -> validate_user(params) end,
        fn -> retrieve_user(params) end,
      ]
      |> Enum.map(&Task.async/1)
      |> Enum.map(&Task.await/1)

      case valid && !is_nil(user) do
      true ->
        conn
        |> put_private(:steam_user, user)
      false ->
        set_errors!(conn, [error("invalid_user", "Invalid steam user")])
    end
    end
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("invalid_openid", "Invalid openid response received")])
  end

  @doc false
  @spec handle_cleanup!(Plug.Conn.t) :: Plug.Conn.t
  def handle_cleanup!(conn) do
    conn
    |> put_private(:steam_user, nil)
  end

  @doc ~S"""
  Fetches the uid field from the response.

  Takes the `steamid` from the `steamuser` saved in the `conn`.
  """
  @spec uid(Plug.Conn.t) :: pos_integer
  def uid(conn) do
    conn.private.steam_user.steamid |> String.to_integer
  end

  @doc ~S"""
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.

  Takes the information from the `steamuser` saved in the `conn`.
  """
  @spec info(Plug.Conn.t) :: Info.t
  def info(conn) do
    user = conn.private.steam_user

    %Info{
      image: user.avatar,
      name: get_in(user, [:realname]),
      location: get_in(user, [:loccountrycode]),
      urls: %{
        Steam: user.profileurl,
      }
    }
  end

  @doc ~S"""
  Stores the raw information obtained from the Steam callback.

  Returns the `steamuser` saved in the `conn` as `raw_info`.
  """
  @spec extra(Plug.Conn.t) :: Extra.t
  def extra(conn) do
    %Extra{
      raw_info: %{
        user: conn.private.steam_user
      }
    }
  end

  @spec retrieve_user(map) :: map | nil
  defp retrieve_user(%{"openid.claimed_id" => claimed_id}) do
    id = case claimed_id do
      "http://steamcommunity.com/openid/id/" <> id -> id
      "https://steamcommunity.com/openid/id/" <> id -> id
      _ -> raise "claimed_id matching error"
    end

    key =
      :ueberauth
      |> Application.fetch_env!(Ueberauth.Strategy.Steam)
      |> Keyword.get(:api_key)
    url = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=" <> key <> "&steamids=" <> id

    with {:ok, %HTTPoison.Response{body: body}} <- HTTPoison.get(url),
         {:ok, user} <- Poison.decode(body, keys: :atoms)
    do
      List.first(user.response.players)
    else
      _ -> nil
    end
  end

  @spec validate_user(map) :: boolean
  defp validate_user(params) do
    query =
      params
      |> Enum.filter(fn {key, _value} -> String.starts_with?(key, "openid.") end)
      |> Enum.into(%{})
      |> Map.put("openid.mode", "check_authentication")
      |> URI.encode_query

    case HTTPoison.get("https://steamcommunity.com/openid/login?" <> query) do
      {:ok, %HTTPoison.Response{body: body, status_code: 200}} ->
        String.contains?(body, "is_valid:true\n")
      _ ->
        false
    end
  end


  @doc false
  @spec credentials(Plug.Conn.t) :: Ueberauth.Auth.Credentials.t
  def credentials(_conn), do: %Ueberauth.Auth.Credentials{}

  # auth/1 default is provided by `use Ueberauth.Strategy` and is
  # intentionally left unimplemented here so the injected default
  # will be used. If you need to override it, implement `auth/1`
  # to return an `%Ueberauth.Auth{}` struct.
end
