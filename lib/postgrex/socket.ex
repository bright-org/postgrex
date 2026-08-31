defmodule Postgrex.Socket do
  @moduledoc false

  def connect(host, port, timeout) do
    with {:ok, addr} <- resolve(host),
         {:ok, sock} <- :socket.open(:inet, :stream, :tcp) do
      case do_connect(sock, addr, port, timeout) do
        :ok ->
          {:ok, sock}

        {:error, reason} ->
          _ = :socket.close(sock)
          {:error, reason}
      end
    end
  end

  def send(sock, data) do
    do_send(sock, IO.iodata_to_binary(data))
  end

  def recv(sock, length, timeout) do
    :socket.recv(sock, length, timeout)
  end

  def close(sock) do
    :socket.close(sock)
  end

  def shutdown(sock, how) do
    :socket.shutdown(sock, how)
  end

  def peername(sock) do
    case :socket.peername(sock) do
      {:ok, %{addr: addr, port: port}} -> {:ok, {addr, port}}
      other -> other
    end
  end

  defp resolve(addr) when is_tuple(addr), do: {:ok, addr}

  defp resolve({:local, _path}) do
    {:error, :notsup}
  end

  defp resolve(host) do
    :inet.getaddr(host, :inet)
  end

  defp do_connect(_sock, {:local, _path}, _port, _timeout) do
    {:error, :notsup}
  end

  defp do_connect(sock, addr, port, timeout) do
    sockaddr = %{family: :inet, addr: addr, port: port}

    if function_exported?(:socket, :connect, 3) do
      :socket.connect(sock, sockaddr, timeout)
    else
      :socket.connect(sock, sockaddr)
    end
  end

  defp do_send(sock, data) do
    case :socket.send(sock, data) do
      :ok -> :ok
      {:ok, <<>>} -> :ok
      {:ok, rest} -> do_send(sock, rest)
      {:error, _} = error -> error
    end
  end
end
