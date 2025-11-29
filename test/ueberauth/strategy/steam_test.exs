defmodule Ueberauth.Strategy.SteamTest do
  use ExUnit.Case, async: false
  use Plug.Test

  alias Ueberauth.Strategy.Steam

  @sample_user %{avatar: "https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/f3/f3dsf34324eawdasdas3rwe.jpg",
       avatarfull: "https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/f3/f3dsf34324eawdasdas3rwe_full.jpg",
       avatarmedium: "https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/f3/f3dsf34324eawdasdas3rwe_medium.jpg",
       communityvisibilitystate: 1, lastlogoff: 234234234, loccityid: 36148,
       loccountrycode: "NL", locstatecode: "03", personaname: "Sample",
       personastate: 0, personastateflags: 0,
       primaryclanid: "435345345", profilestate: 1,
       profileurl: "http://steamcommunity.com/id/sample/",
       realname: "Sample Sample", steamid: "765309403423",
       timecreated: 452342342}
  @sample_response %{response: %{players: [@sample_user]}}
  @optional_fields [:loccountrycode, :realname]

  describe "handle_request!" do
    test "redirects" do
      conn = Steam.handle_request! conn(:get, "http://example.com/path")

      assert conn.state == :sent
      assert conn.status == 302
    end

    test "redirects to the right url" do
      conn = Steam.handle_request! conn(:get, "http://example.com/path")

      {"location", location} = List.keyfind(conn.resp_headers, "location", 0)

      assert String.contains?(location, "https://steamcommunity.com/openid/login?")
      assert String.contains?(location, "openid.realm=http%3A%2F%2Fexample.com")
      assert String.contains?(location, "openid.return_to=http%3A%2F%2Fexample.com")
    end

    test "includes state when session csrf token exists" do
      session_token = String.duplicate("A", 24)
      conn = conn(:get, "http://example.com/path") |> init_test_session(%{"_csrf_token" => session_token})

      conn = Steam.handle_request!(conn)
      {"location", location} = List.keyfind(conn.resp_headers, "location", 0)

      # return_to should include a state param that contains the session token
      assert String.contains?(location, "openid.return_to=")
      # The state value will be url encoded inside the return_to param
      # it will therefore appear as state%3D in the top-level querystring
      assert String.contains?(location, "state%3D")
    end
  end

  describe "handle_callback!" do
    setup do
      # Configure API key in the application env for the tests
      Application.put_env(:ueberauth, Ueberauth.Strategy.Steam, api_key: "API_KEY")

      on_exit(fn -> Application.delete_env(:ueberauth, Ueberauth.Strategy.Steam) end)

      :ok
    end

    defp callback(params \\ %{}, session \\ %{}) do
      conn = conn(:get, "http://example.com/path/callback") |> init_test_session(session)
      conn = %{conn | params: params}

      Steam.handle_callback!(conn)
    end

    test "error for invalid callback parameters" do
      conn = callback()

      assert conn.assigns == %{
          ueberauth_failure: %Ueberauth.Failure{errors: [
            %Ueberauth.Failure.Error{message: "Invalid openid response received", message_key: "invalid_openid"}
          ], provider: nil, strategy: nil}
        }
    end

    test "error for missing user valid information" do
      :meck.new HTTPoison, [:passthrough]
      on_exit(fn -> :meck.unload end)
      :meck.expect HTTPoison, :get, fn
        "https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fsteamcommunity.com%2Fopenid%2Fid%2F12345&openid.mode=check_authentication" ->
          {:ok, %HTTPoison.Response{body: "", status_code: 200}}
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=API_KEY&steamids=12345" ->
          {:ok, %HTTPoison.Response{body: Poison.encode!(@sample_response), status_code: 200}}
      end

      conn =
        callback(%{
          "openid.mode" => "id_res",
          "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345"
        })

      assert conn.assigns == %{
          ueberauth_failure: %Ueberauth.Failure{errors: [
            %Ueberauth.Failure.Error{message: "Invalid steam user", message_key: "invalid_user"}
          ], provider: nil, strategy: nil}
        }
    end

    test "error for invalid user callback" do
      :meck.new HTTPoison, [:passthrough]
      on_exit(fn -> :meck.unload end)
      :meck.expect HTTPoison, :get, fn
        "https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fsteamcommunity.com%2Fopenid%2Fid%2F12345&openid.mode=check_authentication" ->
          {:ok, %HTTPoison.Response{body: "is_valid:false\n", status_code: 200}}
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=API_KEY&steamids=12345" ->
          {:ok, %HTTPoison.Response{body: Poison.encode!(@sample_response), status_code: 200}}
      end

      conn =
        callback(%{
          "openid.mode" => "id_res",
          "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345"
        })

      assert conn.assigns == %{
          ueberauth_failure: %Ueberauth.Failure{errors: [
            %Ueberauth.Failure.Error{message: "Invalid steam user", message_key: "invalid_user"}
          ], provider: nil, strategy: nil}
        }
    end

    test "error for invalid user data" do
      :meck.new HTTPoison, [:passthrough]
      on_exit(fn -> :meck.unload end)
      :meck.expect HTTPoison, :get, fn
        "https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fsteamcommunity.com%2Fopenid%2Fid%2F12345&openid.mode=check_authentication" ->
          {:ok, %HTTPoison.Response{body: "is_valid:true\n", status_code: 200}}
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=API_KEY&steamids=12345" ->
          {:ok, %HTTPoison.Response{body: "{{{{{{{", status_code: 200}}
      end

      conn =
        callback(%{
          "openid.mode" => "id_res",
          "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345"
        })

      assert conn.assigns == %{
          ueberauth_failure: %Ueberauth.Failure{errors: [
            %Ueberauth.Failure.Error{message: "Invalid steam user", message_key: "invalid_user"}
          ], provider: nil, strategy: nil}
        }
    end

    test "error when session state exists but missing in callback" do
      session_state = String.duplicate("B", 24)

      conn =
        callback(%{"openid.mode" => "id_res", "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345"}, %{"ueberauth_steam_state" => session_state})

      assert conn.assigns == %{
               ueberauth_failure: %Ueberauth.Failure{errors: [
                 %Ueberauth.Failure.Error{message: "Cross-Site Request Forgery attack", message_key: "csrf_attack"}
               ], provider: nil, strategy: nil}
             }
    end

    test "accepts cookie state when session absent" do
      cookie_state = String.duplicate("D", 24)

      conn =
        conn(:get, "http://example.com/path/callback")
        |> put_req_header("cookie", "ueberauth.state_param=#{cookie_state}")
        |> Map.put(:req_cookies, %{"ueberauth.state_param" => cookie_state})
        |> Map.put(:params, %{"openid.mode" => "id_res", "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345", "state" => cookie_state})

      # Prepare HTTPoison expectations for normal happy path
      :meck.new HTTPoison, [:passthrough]
      on_exit(fn -> :meck.unload end)
      :meck.expect HTTPoison, :get, fn
        "https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fsteamcommunity.com%2Fopenid%2Fid%2F12345&openid.mode=check_authentication" ->
          {:ok, %HTTPoison.Response{body: "is_valid:true\n", status_code: 200}}
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=API_KEY&steamids=12345" ->
          {:ok, %HTTPoison.Response{body: Poison.encode!(@sample_response), status_code: 200}}
      end

      # sanity-check the request header has the cookie we set, otherwise the
      # code that extracts cookies won't see it
      assert Plug.Conn.get_req_header(conn, "cookie") != []

      conn = Steam.handle_callback!(conn)

      assert conn.assigns == %{}
      assert conn.private[:steam_user] == @sample_user
    end

    test "rejects when cookie state exists but does not match returned one" do
      cookie_state = String.duplicate("E", 24)

      conn =
        conn(:get, "http://example.com/path/callback")
        |> put_req_header("cookie", "ueberauth.state_param=#{cookie_state}")
        |> Map.put(:req_cookies, %{"ueberauth.state_param" => cookie_state})
        |> Map.put(:params, %{"openid.mode" => "id_res", "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345", "state" => "mismatch"})

      # sanity-check the request header has the cookie we set
      assert Plug.Conn.get_req_header(conn, "cookie") != []

      conn = Steam.handle_callback!(conn)

      assert conn.assigns == %{
               ueberauth_failure: %Ueberauth.Failure{errors: [
                 %Ueberauth.Failure.Error{message: "Cross-Site Request Forgery attack", message_key: "csrf_attack"}
               ], provider: nil, strategy: nil}
             }
    end

    test "error when session state exists but does not match returned one" do
      session_state = String.duplicate("B", 24)

      conn =
        callback(%{"openid.mode" => "id_res", "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345", "state" => "mismatch"}, %{"ueberauth_steam_state" => session_state})

      assert conn.assigns == %{
               ueberauth_failure: %Ueberauth.Failure{errors: [
                 %Ueberauth.Failure.Error{message: "Cross-Site Request Forgery attack", message_key: "csrf_attack"}
               ], provider: nil, strategy: nil}
             }
    end

    test "success for valid user and valid user data" do
      session_state = String.duplicate("C", 24)
      :meck.new HTTPoison, [:passthrough]
      on_exit(fn -> :meck.unload end)
      :meck.expect HTTPoison, :get, fn
        "https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fsteamcommunity.com%2Fopenid%2Fid%2F12345&openid.mode=check_authentication" ->
          {:ok, %HTTPoison.Response{body: "is_valid:true\n", status_code: 200}}
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=API_KEY&steamids=12345" ->
          {:ok, %HTTPoison.Response{body: Poison.encode!(@sample_response), status_code: 200}}
      end

      conn =
        callback(%{
          "openid.mode" => "id_res",
          "openid.claimed_id" => "http://steamcommunity.com/openid/id/12345",
          "state" => session_state
        }, %{"ueberauth_steam_state" => session_state})

      assert conn.assigns == %{}
      assert conn.private[:steam_user] == @sample_user
    end
  end

  describe "info retrievers fetch" do
    setup do
      conn = %{conn(:get, "http://example.com/path/callback") | private: %{steam_user: @sample_user}}

      conn = Steam.handle_callback! conn

      [conn: conn]
    end

    test "uid", %{conn: conn} do
      assert Steam.uid(conn) == 765309403423
    end

    test "info", %{conn: conn} do
      assert Steam.info(conn) == %Ueberauth.Auth.Info{
             image: "https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/f3/f3dsf34324eawdasdas3rwe.jpg",
             location: "NL", name: "Sample Sample",
             urls: %{Steam: "http://steamcommunity.com/id/sample/"}}
    end

    test "extra", %{conn: conn} do
      assert Steam.extra(conn) == %Ueberauth.Auth.Extra{raw_info: %{user: @sample_user}}
    end

    test "credentials", %{conn: conn} do
      assert Steam.credentials(conn) == %Ueberauth.Auth.Credentials{}
    end
  end

  describe "info retrievers fetch (nil optional fields)" do
    setup do
      conn = %{conn(:get, "http://example.com/path/callback") | private: %{steam_user: Map.drop(@sample_user, @optional_fields)}}
      conn = Steam.handle_callback! conn

      [conn: conn]
    end

    test "info", %{conn: conn} do
      auth_info = %Ueberauth.Auth.Info{
            image: "https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/f3/f3dsf34324eawdasdas3rwe.jpg",
            urls: %{Steam: "http://steamcommunity.com/id/sample/"}}
      assert Steam.info(conn) == auth_info
    end
  end

  test "connection is cleaned up" do
    conn = %{conn(:get, "http://example.com/path/callback") | private: %{steam_user: @sample_user}}

    conn =
      conn
      |> Steam.handle_callback!
      |> Steam.handle_cleanup!

    assert conn.private == %{steam_user: nil}
  end
end
