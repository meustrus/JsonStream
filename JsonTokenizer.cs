using System;
using System.Linq;
using System.Text;

namespace SimpleJson
{
    public class JsonTokenizer
    {
        private readonly Encoding _encoding;

        private readonly byte[][] _whitespaceChars;

        private readonly byte[] _nullToken;

        private readonly byte[] _trueToken;

        private readonly byte[] _falseToken;

        private readonly byte[][] _signChars;

        private readonly byte[][] _digitChars;

        private readonly byte[] _decimalChar;

        private readonly byte[] _nanToken;

        private readonly byte[] _quoteChar;

        private readonly byte[] _arrayStartChar;

        private readonly byte[] _arrayEndChar;

        private readonly byte[] _objectStartChar;

        private readonly byte[] _objectEndChar;

        private readonly byte[] _delimiterChar;

        private readonly byte[] _propertyDefChar;

        public JsonTokenizer(Encoding encoding)
        {
            _encoding = encoding;
            _whitespaceChars = new[] {
                encoding.GetBytes(" "),
                encoding.GetBytes("\t"),
                encoding.GetBytes("\n"),
                encoding.GetBytes("\r")
            };
            _nullToken = encoding.GetBytes("null");
            _trueToken = encoding.GetBytes("true");
            _falseToken = encoding.getBytes("false");
            _signChars = new[] {
                encoding.GetBytes("+"),
                encoding.GetBytes("-")
            };
            _digitChars = new[] {
                encoding.GetBytes("0"),
                encoding.GetBytes("1"),
                encoding.GetBytes("2"),
                encoding.GetBytes("3"),
                encoding.GetBytes("4"),
                encoding.GetBytes("5"),
                encoding.GetBytes("6"),
                encoding.GetBytes("7"),
                encoding.GetBytes("8"),
                encoding.GetBytes("9")
            },
            _decimalChar = encoding.GetBytes(".");
            _nanToken = encoding.GetBytes("NaN");
            _quoteChar = encoding.GetBytes("\"");
            _arrayStartChar = encoding.GetBytes("[");
            _arrayEndChar = encoding.GetBytes("]");
            _objectStartChar = encoding.GetBytes("{");
            _objectEndChar = encoding.GetBytes("}");
            _delimiterChar = encoding.GetBytes(",");
            _propertyDefChar = encoding.GetBytes(":");
        }

        public IEnumerable<IJsonToken> ReadJsonTokens(StreamReaderDelegate writeToBuffer)
        {
            return StreamTokenizer.ReadTokens(writeToBuffer, ReadJsonToken);
        }

        private static TokenReadResult<IJsonToken> ReadJsonToken(ArraySegment<byte> buffer)
        {
            var whitespaceAtStart = MatchChars(buffer, _whitespaceChars).Sum(t => t.Length);
            var bufferWithWhitespaceSkipped = buffer.Skip(whitespaceAtStart);

            var successfulResult = JsonTokenReaders
                .Select(r => r(bufferWithWhitespaceSkipped))
                .FirstOrDefault(trr => trr.Success);

            return successfulResult != null
                ? successfulResult
                : new TokenReadResult<IJsonToken>(false, null, whitespaceAtStart);
        }

        private static IEnumerable<T[]> MatchChars<T>(ArraySegment<T> buffer, params T[][] chars)
        {
            var activeBuffer = buffer;
            do
            {
                var match = chars.FirstOrDefault(activeBuffer.StartsWith);
                if (match != null)
                {
                    yield return match;
                    activeBuffer = activeBuffer.Skip(match.Length);
                }
            } while (match != null);
        }

        private IEnumerable<ReadTokenDelegate<IJsonToken>> JsonTokenReaders
        {
            get
            {
                yield return new SimpleToken(JsonTokenType.ArrayStart, _arrayStartChar).ReadToken;
                yield return new SimpleToken(JsonTokenType.ArrayEnd, _arrayEndChar).ReadToken;
                yield return new SimpleToken(JsonTokenType.ObjectStart, _objectStartChar).ReadToken;
                yield return new SimpleToken(JsonTokenType.ObjectEnd, _objectEndChar).ReadToken;
                yield return new SimpleToken(JsonTokenType.Delimiter, _delimiterChar).ReadToken;
                yield return new SimpleToken(JsonTokenType.PropertyDef, _propertyDefChar).ReadToken;
                yield return new SimpleToken(JsonTokenType.Null, _nullToken).ReadToken;
                yield return new BooleanToken(_trueToken, true).ReadToken;
                yield return new BooleanToken(_falseToken, false).ReadToken;
                yield return ReadJsonNumberToken;
            }
        }

        private TokenReadResult<IJsonToken> ReadJsonNumberToken(ArraySegment<byte> buffer)
        {
            if (buffer.StartsWith(_nanToken))
            {
                return new NumberOrStringToken(JsonTokenType.Number, "NaN");
            }

            var matchingSign = _signChars.FirstOrDefault(buffer.StartsWith);
            var numSignBytes = matchingSign != null ? matchingSign.Length : 0;
            var bufferAfterSign = buffer.Skip(numSignBytes);

            var numDigitBytes = MatchChars(bufferAfterSign, _digitChars).Sum(t => t.Length);
            if (numDigitBytes <= 0)
            {
                return new TokenReadResult<IJsonToken>(false, null, 0);
            }

            var bufferAfterDigits = bufferAfterSign.Skip(numDigitBytes);

            if (bufferAfterDigits.StartsWith(_decimalChar))
            {
                var bufferAfterDecimal = bufferAfterDigits.Skip(_decimalChar.Length);
                var numDecimalBytes = MatchChars(bufferAfterDecimal, _digitChars).Sum(t => t.Length);
                if (numDecimalBytes > 0) {
                    var numBytes = numSignBytes + numDigitBytes + _decimalChar.Length + numDecimalBytes;
                    return BuildJsonNumberTokenResult(buffer, numBytes);
                }
            }

            return BuildJsonNumberTokenResult(buffer, numSignBytes + numDigitBytes);
        }

        private TokenReadResult<IJsonToken> BuildJsonNumberTokenResult(ArraySegment<byte> buffer, int numBytes)
        {
            var tokenData = _encoding.GetString(buffer.Array, buffer.Offset, numBytes);
            var token = new NumberOrStringToken(JsonTokenType.Number, tokenData);
            return new TokenReadResult<IJsonToken>(true, token, numBytes);
        }

        private TokenReadResult<IJsonToken> ReadJsonStringToken(ArraySegment<byte> buffer)
        {
            // TODO
            return new TokenReadResult<IJsonToken>(false, null, 0);
        }

        private struct SimpleJsonToken : IJsonToken
        {
            public JsonTokenType Type { get; }

            public bool? AsBoolean { get { return null; } }

            public int? AsInt { get { return null; } }

            public float? AsFloat { get { return null; } }

            public string AsString { get { return null; } }

            private readonly byte[] _encodedToken;

            public SimpleJsonToken(JsonTokenType type, byte[] encodedToken)
            {
                Type = type;
                EncodedToken = encodedToken;
            }

            public TokenReadResult<IJsonToken> ReadToken(ArraySegment<T> buffer)
            {
                return buffer.StartsWith(_encodedToken)
                    ? new TokenReadResult<IJsonToken>(true, this, _encodedToken.Length)
                    : new TokenReadResult<IJsonToken>(false, null, 0);
            }
        }

        private struct BooleanToken : IJsonToken
        {
            public override JsonTokenType Type { get { return JsonTokenType.Boolean; } }

            public override bool? AsBoolean { get; }

            public int? AsInt { get { return null; } }

            public float? AsFloat { get { return null; } }

            public string AsString { get { return null; } }

            private readonly byte[] _encodedToken;

            public BooleanToken(byte[] encodedToken, bool value)
            {
                EncodedToken = encodedToken;
                AsBoolean = value;
            }

            public TokenReadResult<IJsonToken> ReadToken(ArraySegment<T> buffer)
            {
                return buffer.StartsWith(_encodedToken)
                    ? new TokenReadResult<IJsonToken>(true, this, _encodedToken.Length)
                    : new TokenReadResult<IJsonToken>(false, null, 0);
            }
        }

        private struct NumberOrStringToken : IJsonToken
        {
            public override JsonTokenType Type { get; }

            public bool? AsBoolean { get { return null; } }

            public override int? AsInt { get { return AsString.AsInt(); } }

            public override float? AsFloat { get { return AsString.AsFloat(); } }

            public override string AsString { get; }

            public NumberToken(JsonTokenType type, string value)
            {
                Type = type;
                AsString = value;
            }
        }
    }

    public interface IJsonToken
    {
        JsonTokenType Type { get; }

        bool? AsBoolean { get; }

        int? AsInt { get; }

        float? AsFloat { get; }

        string AsString { get; }
    }

    public enum JsonTokenType
    {
        Null,
        Boolean,
        Number,
        String,
        ArrayStart,
        ArrayEnd,
        ObjectStart,
        ObjectEnd,
        Delimiter,
        PropertyDef,
    }

    public static class StreamTokenizer
    {
        private const int InitialBufferSize = 4096;

        private static readonly Func<ArraySegment<byte>, int> GetMinimumFreeSpace
            = buffer => buffer.Array.Length * 3 / 4;

        public static IEnumerable<T> ReadTokens<T>(StreamReaderDelegate writeToBuffer, ReadTokenDelegate<T> readToken)
        {
            var buffer = new ArraySegment<byte>(new byte[InitialBufferSize], 0, 0);
            var streamOffset = 0;

            do
            {
                buffer = ReadFromStream(buffer, writeToBuffer);

                while (buffer.Count > 0)
                {
                    var result = readToken(buffer);
                    streamOffset += result.BytesConsumed;
                    buffer = buffer.Skip(result.BytesConsumed);

                    if (result.Success)
                    {
                        yield return result.Token;
                    }
                    else
                    {
                        break;
                    }
                }

                if (buffer.Offset == 0)
                {
                    throw new TokenParseException("Unable to parse token", streamOffset);
                }
            }
            while (buffer.Offset + buffer.Count >= buffer.Array.Length);
        }

        private static ArraySegment<byte> ReadFromStream(ArraySegment<byte> buffer, StreamReaderDelegate writeToBuffer)
        {
            var mostlyEmptyBuffer = ReclaimBufferStart(buffer, GetMinimumFreeSpace(buffer));
            var bufferEndOffset = mostlyEmptyBuffer.Offset + mostlyEmptyBuffer.Count;
            var availableBufferLength = mostlyEmptyBuffer.Array.Length - bufferEndOffset;
            var readBytes = writeToBuffer(mostlyEmptyBuffer.Array, bufferEndOffset, availableBufferLength);

            return new ArraySegment<byte>(
                mostlyEmptyBuffer.Array,
                mostlyEmptyBuffer.Offset,
                mostlyEmptyBuffer.Count + readBytes
            );
        }

        private static ArraySegment<T> ReclaimBufferStart<T>(ArraySegment<T> buffer, int minFreeSpace)
        {
            var minArrayLength = buffer.Count + minFreeSpace;
            var newBytes = buffer.Array.Length >= minArrayLength ? buffer.Array : new T[minArrayLength];

            if (buffer.Count > 0)
            {
                Array.Copy(buffer.Array, buffer.Offset, newBytes, 0, buffer.Count);
            }

            return new ArraySegment<T>(newBytes, 0, buffer.Count);
        }
    }

    public delegate int StreamReaderDelegate(byte[], int, int);

    public delegate TokenReadResult<T> ReadTokenDelegate<T>(ArraySegment<byte> buffer);

    public struct TokenReadResult<T>
    {
        public bool Success { get; }

        public T Token { get; }

        public int BytesConsumed { get; }

        public TokenReadResult(bool success, T token, int bytesConsumed)
        {
            Success = success;
            Token = token;
            BytesConsumed = bytesConsumed;
        }
    }

    public class TokenParseException : Exception
    {
        public int StreamOffset { get; }

        public TokenParseException(int streamOffset, string message) : base($"{message} at offset {streamOffset}")
        {
            StreamOffset = streamOffset;
        }
    }

    internal static class ArraySegmentExtensions
    {
        public static ArraySegment<T> Skip<T>(this ArraySegment<T> segment, int skipLength)
        {
            return new ArraySegment<T>(segment.Array, segment.Offset + skipLength, segment.Count - skipLength);
        }

        public static ArraySegment<T> Take<T>(this ArraySegment<T> segment, int maxElems)
        {
            return new ArraySegment<T>(segment.Array, segment.Offset, Math.Min(segment.Count, maxElems));
        }

        public static bool StartsWith<T>(this ArraySegment<T> segment, T[] sequence)
        {
            return segment.Take(sequence.Length).SequenceEqual(sequence);
        }
    }

    internal static class TryParseExtensions
    {
        private delegate bool TryParseDelegate<in TIn, TOut>(TIn input, out TOut output);

        private static TOut? TryParse<TIn, TOut>(this TIn input, TryParseDelegate<TIn, TOut> tryParse)
            where TOut : struct
        {
            TOut output;
            return tryParse(input, out output) ? (TOut?) output : null;
        }

        public static int? AsInt(this string input)
        {
            return input.TryParse<string, int>(int.TryParse);
        }

        public static float? AsFloat(this string input)
        {
            return input.TryParse<string, float>(float.TryParse);
        }
    }
}
