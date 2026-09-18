defmodule Postgrex.SCRAM do
  @moduledoc false

  alias Postgrex.SCRAM

  @hash_length 32
  @nonce_length 24
  @nonce_rand_bytes div(@nonce_length * 6, 8)
  @cb_gs2_header "p=tls-server-end-point,,"

  # Chooses the SCRAM mechanism and gs2 header from the mechanisms the server offered.
  def negotiate_channel_binding(server_mechanisms, sock, mode) do
    offered = parse_mechanisms(server_mechanisms)
    plus_offered? = "SCRAM-SHA-256-PLUS" in offered
    tls? = match?({:ssl, _}, sock)

    cond do
      mode == :disable ->
        {:ok, {"SCRAM-SHA-256", "n,,", ""}}

      tls? and plus_offered? ->
        case cert_hash(sock) do
          {:ok, hash} ->
            {:ok, {"SCRAM-SHA-256-PLUS", @cb_gs2_header, hash}}

          :error when mode == :require ->
            {:error,
             %Postgrex.Error{
               message:
                 "channel binding is required but the server certificate has no usable hash"
             }}

          # Fallback
          :error ->
            {:ok, {"SCRAM-SHA-256", "n,,", ""}}
        end

      mode == :require ->
        {:error,
         %Postgrex.Error{
           message:
             "channel binding is required but not offered by the server, or the connection is not using SSL"
         }}

      true ->
        cbind_flag = if tls?, do: "y,,", else: "n,,"
        {:ok, {"SCRAM-SHA-256", cbind_flag, ""}}
    end
  end

  def client_first({mechanism, gs2_header, _cbind_data}) do
    nonce = @nonce_rand_bytes |> :crypto.strong_rand_bytes() |> Base.encode64()
    sasl_data = [gs2_header, "n=,r=", nonce]
    size = <<IO.iodata_length(sasl_data)::signed-size(32)>>
    [mechanism, 0, size, sasl_data]
  end

  # AtomVM has failed to resolve client_final/3 specifically; keep a thin alias.
  def client_final(data, cb, opts), do: finish_client(data, cb, opts)

  def finish_client(data, {_mechanism, gs2_header, cbind_data}, opts) do
    server = parse_server_data(data)
    server_r = Map.get(server, ?r)
    server_s_b64 = Map.get(server, ?s)
    server_i_bin = Map.get(server, ?i)
    {:ok, server_s} = Base.decode64(server_s_b64)
    server_i = :erlang.binary_to_integer(server_i_bin)
    pass = Keyword.fetch!(opts, :password)
    {client_key, server_key} = calculate_client_server_keys(pass, server_s, server_i)
    cbind_input = Base.encode64(:erlang.iolist_to_binary([gs2_header, cbind_data]))
    message_without_proof = ["c=", cbind_input, ",r=", server_r]
    client_nonce = :erlang.binary_part(server_r, 0, @nonce_length)

    message = [
      "n=,r=",
      client_nonce,
      ",r=",
      server_r,
      ",s=",
      server_s_b64,
      ",i=",
      server_i_bin,
      ?,
    ]

    auth_message = :erlang.iolist_to_binary([message | message_without_proof])
    hashed = :crypto.hash(:sha256, client_key)
    client_sig = hmac(:sha256, hashed, auth_message)
    # AtomVM crypto has no exor/2 — XOR client_key with client_sig ourselves.
    proof = Base.encode64(binary_xor(client_key, client_sig))

    scram_state = %{
      salt: server_s,
      iterations: server_i,
      auth_message: auth_message,
      server_key: server_key
    }

    {[message_without_proof, ",p=", proof], scram_state}
  end

  def verify_server(data, scram_state, opts) do
    data
    |> parse_server_data()
    |> do_verify_server(scram_state, opts)
  end

  defp parse_mechanisms(data) do
    data |> :binary.split(<<0>>, [:global]) |> Enum.reject(&(&1 == ""))
  end

  # RFC 5929 tls-server-end-point
  defp cert_hash({:ssl, sslsock}) do
    with {:ok, der} <- :ssl.peercert(sslsock),
         {:Certificate, _tbs, sig_alg, _sig} <- :public_key.pkix_decode_cert(der, :plain),
         {_tag, oid, _params} <- sig_alg,
         {digest, _sign} when digest != :none <- pkix_sign_type(oid) do
      # Ref: https://www.rfc-editor.org/info/rfc5929/#section-4.1
      digest = if digest in [:md5, :sha], do: :sha256, else: digest
      {:ok, :crypto.hash(digest, der)}
    else
      _ -> :error
    end
  end

  defp pkix_sign_type(oid) do
    :public_key.pkix_sign_types(oid)
  rescue
    _ -> {:none, :unknown}
  end

  def do_verify_server(server, scram_state, opts) do
    cond do
      Map.has_key?(server, ?e) ->
        server_e = Map.get(server, ?e)
        msg = "error received in SCRAM server final message: #{inspect(server_e)}"
        {:error, %Postgrex.Error{message: msg}}

      Map.has_key?(server, ?v) ->
        server_v = Map.get(server, ?v)
        {:ok, server_sig} = Base.decode64(server_v)

        server_key =
          case Map.get(scram_state, :server_key) do
            nil ->
              pass = Keyword.fetch!(opts, :password)
              {_client_key, key} =
                calculate_client_server_keys(pass, Map.get(scram_state, :salt), Map.get(scram_state, :iterations))

              key

            key ->
              key
          end

        expected_server_sig = hmac(:sha256, server_key, Map.get(scram_state, :auth_message))

        if expected_server_sig == server_sig do
          :ok
        else
          {:error, %Postgrex.Error{message: "cannot verify SCRAM server signature"}}
        end

      true ->
        msg = "unsupported SCRAM server final message: #{inspect(server)}"
        {:error, %Postgrex.Error{message: msg}}
    end
  end

  # Avoid `for`/`into` (FunT) — AtomVM has failed to resolve client_final when funs are present.
  def parse_server_data(data) do
    parts = :binary.split(data, ",", [:global])
    parse_server_parts(parts, %{})
  end

  def parse_server_parts([], acc), do: acc

  def parse_server_parts([kv | rest], acc) do
    <<k, "=", v::binary>> = kv
    parse_server_parts(rest, Map.put(acc, k, v))
  end

  defp create_cache_key(pass, salt, iterations) do
    {:crypto.hash(:sha256, pass), salt, iterations}
  end

  # AtomVM can fail to resolve Elixir defp locals (undef). Keep helpers exported.
  def calculate_client_server_keys(pass, salt, iterations) do
    # Use PBKDF2 NIF instead of recursive iterate/4 (AtomVM undef on that path).
    salted_pass = :crypto.pbkdf2_hmac(:sha256, pass, salt, iterations, @hash_length)
    client_key = hmac(:sha256, salted_pass, "Client Key")
    server_key = hmac(:sha256, salted_pass, "Server Key")

    {client_key, server_key}
  end

  def hash_password(secret, salt, iterations) do
    hash_password(secret, salt, iterations, 1, [], 0)
  end

  def hash_password(_secret, _salt, _iterations, _block_index, acc, length)
      when length >= @hash_length do
    acc
    |> IO.iodata_to_binary()
    |> binary_part(0, @hash_length)
  end

  def hash_password(secret, salt, iterations, block_index, acc, length) do
    initial = hmac(:sha256, secret, <<salt::binary, block_index::integer-size(32)>>)
    block = iterate(secret, iterations - 1, initial, initial)
    length = byte_size(block) + length
    hash_password(secret, salt, iterations, block_index + 1, [acc | block], length)
  end

  def iterate(_secret, 0, _prev, acc), do: acc

  def iterate(secret, iteration, prev, acc) do
    next = hmac(:sha256, secret, prev)
    iterate(secret, iteration - 1, next, binary_xor(next, acc))
  end

  # AtomVM does not export :crypto.exor/2.
  def binary_xor(a, b) when byte_size(a) == byte_size(b) do
    binary_xor(a, b, <<>>)
  end

  def binary_xor(<<>>, <<>>, acc), do: acc

  def binary_xor(<<x, a::binary>>, <<y, b::binary>>, acc) do
    binary_xor(a, b, <<acc::binary, :erlang.bxor(x, y)>>)
  end

  # :crypto.mac/4 was added in OTP-22.1, and :crypto.hmac/3 removed in OTP-24.
  # Check which function to use at compile time to avoid doing a round-trip
  # to the code server on every call. The downside is this module won't work
  # if it's compiled on OTP-22.0 or older then executed on OTP-24 or newer.
  if Code.ensure_loaded?(:crypto) and function_exported?(:crypto, :mac, 4) do
    def hmac(type, key, data), do: :crypto.mac(:hmac, type, key, data)
  else
    def hmac(type, key, data), do: :crypto.hmac(type, key, data)
  end
end
