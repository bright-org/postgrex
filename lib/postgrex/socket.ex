defmodule Postgrex.Socket do
  @moduledoc false

  def connect(host, port, timeout, opts \\ []) do
    with {:ok, addr} <- resolve(host),
         {:ok, sock} <- :socket.open(:inet, :stream, :tcp),
         :ok <- apply_opts(sock, opts) do
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
    stop_reader(sock)
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

  def setopts(sock, opts) do
    apply_setopts(sock, opts)
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
    parent = self()

    worker =
      spawn(fn ->
        Kernel.send(parent, {self(), :socket.connect(sock, sockaddr)})
      end)

    receive do
      {^worker, result} ->
        result
    after
      timeout ->
        _ = :socket.close(sock)
        {:error, :timeout}
    end
  end

  defp apply_opts(_sock, []), do: :ok

  defp apply_opts(sock, [opt | rest]) do
    case map_connect_opt(opt) do
      :ignore ->
        apply_opts(sock, rest)

      {:setopt, key, value} ->
        case :socket.setopt(sock, key, value) do
          :ok -> apply_opts(sock, rest)
          {:error, _} = error -> error
        end
    end
  end

  defp apply_setopts(_sock, []), do: :ok

  defp apply_setopts(sock, [opt | rest]) do
    case apply_setopt(sock, opt) do
      :ok -> apply_setopts(sock, rest)
      {:error, _} = error -> error
    end
  end

  defp map_connect_opt(:reuseaddr), do: {:setopt, {:socket, :reuseaddr}, true}
  defp map_connect_opt({:reuseaddr, value}), do: {:setopt, {:socket, :reuseaddr}, value}
  defp map_connect_opt({:recbuf, n}), do: {:setopt, {:otp, :recvbuf}, n}
  defp map_connect_opt({:buffer, n}), do: {:setopt, {:otp, :recvbuf}, n}
  defp map_connect_opt(_), do: :ignore

  defp apply_setopt(sock, {:active, :once}) do
    start_reader(sock)
    :ok
  end

  defp apply_setopt(sock, {:active, false}) do
    stop_reader(sock)
    :ok
  end

  defp apply_setopt(sock, opt) do
    case map_connect_opt(opt) do
      :ignore -> :ok
      {:setopt, key, value} -> :socket.setopt(sock, key, value)
    end
  end

  defp start_reader(sock) do
    stop_reader(sock)
    owner = self()

    pid =
      spawn(fn ->
        case :socket.recv(sock, 0, :infinity) do
          {:ok, data} -> Kernel.send(owner, {:tcp, sock, data})
          {:error, :closed} -> Kernel.send(owner, {:tcp_closed, sock})
          {:error, reason} -> Kernel.send(owner, {:tcp_error, sock, reason})
        end
      end)

    Process.put({__MODULE__, sock}, pid)
    :ok
  end

  defp stop_reader(sock) do
    case Process.get({__MODULE__, sock}) do
      pid when is_pid(pid) ->
        Process.exit(pid, :kill)
        Process.delete({__MODULE__, sock})
        :ok

      _ ->
        :ok
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
