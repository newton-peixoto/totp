defmodule NewtTotp do
  @duration 30
  @digit_count 6

  import Bitwise

  @spec generate_secret() :: binary()
  def generate_secret do
    :crypto.strong_rand_bytes(20) |> Base.encode32
  end

  @spec generate_totp(binary()) :: binary()
  def generate_totp(key) do
    {:ok, key} = Base.decode32(key)
    key
    |> hmac(calculate_T())
    |> truncate()
  end

  @spec valid?(binary(), any()) :: boolean()
  def valid?(secret, otp, since \\ nil),
    do: otp == generate_totp(secret) and not has_been_used?(since)

  #RFC4226 https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
  defp truncate(hash) do
    # getting the last byte and masking it so we get a valid index
    offset = :binary.last(hash) &&& 0x0F
    # Extract 4 bytes starting from the calculated offset
    <<_::binary-size(offset), extracted_value::integer-size(32), _rest::binary>> = hash

    # Ensure the extracted value is positive
    extracted_positive_value = extracted_value &&& 0x7FFFFFFF

    # taking this number module to get the 06 digits
    otp = rem(extracted_positive_value, :math.pow(10, @digit_count) |> round())

    formatted_otp =
      otp
      |> Integer.to_string()
      |> String.pad_leading(6, "0")

    formatted_otp
  end

  defp hmac(key, t) do
    :crypto.mac(:hmac, :sha, key, t)
  end

  defp calculate_T(), do: <<Integer.floor_div(now_unix(), @duration)::64>>

  defp has_been_used?(nil), do: false

  defp has_been_used?(since),
    do: Integer.floor_div(now_unix(), @duration) <= Integer.floor_div(since, @duration)

  defp now_unix(), do: DateTime.utc_now() |> DateTime.to_unix()
end
