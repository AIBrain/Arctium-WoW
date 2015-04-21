/*
 * Copyright (C) 2012-2014 Arctium Emulation <http://arctium.org>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace AuthServer.Network.Packets
{
    using System;
    using System.IO;
    using System.Text;
    using Constants.Net;
    using Framework.Misc;

    public class AuthPacket
    {
        public AuthPacketHeader Header { get; set; }
        public byte[] Data { get; set; }
        public int ProcessedBytes { get; set; }

        object stream;
        byte bytePart;
        byte preByte;
        int count;

        public AuthPacket()
        {
            this.stream = new BinaryWriter(new MemoryStream());
        }

        public AuthPacket(byte[] data, int size)
        {
            this.stream = new BinaryReader(new MemoryStream(data));

            this.Header = new AuthPacketHeader {
                                                   Message = this.Read< byte >( 6 )
                                               };

            if (this.Read<bool>(1))
                this.Header.Channel = (AuthChannel)this.Read<byte>(4);

            this.Header.Message = (ushort)((this.Header.Message + 0x3F) << (byte)this.Header.Channel);

            this.Data = new byte[size];

            Buffer.BlockCopy(data, 0, this.Data, 0, size);
        }

        public AuthPacket(AuthServerMessage message, AuthChannel channel = AuthChannel.Authentication)
        {
            this.stream = new BinaryWriter(new MemoryStream());

            this.Header = new AuthPacketHeader {
                                                   Message = ( ushort ) message,
                                                   Channel = channel
                                               };

            var hasChannel = channel != AuthChannel.Authentication;
            var msg = this.Header.Message >= 0x7E ? (this.Header.Message >> (byte)channel) - 0x3F : this.Header.Message - 0x3F;

            this.Write(msg, 6);
            this.Write(hasChannel, 1);

            if (hasChannel)
                this.Write((byte)this.Header.Channel, 4);
        }

        public void Finish()
        {
            var writer = this.stream as BinaryWriter;

            this.Data = new byte[writer.BaseStream.Length];

            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            for (int i = 0; i < this.Data.Length; i++)
                this.Data[i] = (byte)writer.BaseStream.ReadByte();

            writer.Dispose();
        }

        #region Reader
        public T Read<T>()
        {
            var reader = this.stream as BinaryReader;

            if (reader == null)
                throw new InvalidOperationException("");

            return reader.Read<T>();
        }

        public byte[] Read(int count)
        {
            var reader = this.stream as BinaryReader;

            if (reader == null)
                throw new InvalidOperationException("");

            this.ProcessedBytes += count;

            return reader.ReadBytes(count);
        }

        public string ReadString(int count)
        {
            return Encoding.UTF8.GetString(this.Read(count));
        }

        public T Read<T>(int bits)
        {
            ulong value = 0;
            var bitsToRead = 0;

            while (bits != 0)
            {
                if ((this.count % 8) == 0)
                {
                    this.bytePart = this.Read<byte>();

                    this.ProcessedBytes += 1;
                }

                var shiftedBits = this.count & 7;
                bitsToRead = 8 - shiftedBits;

                if (bitsToRead >= bits)
                    bitsToRead = bits;

                bits -= bitsToRead;

                value |= (uint)((this.bytePart >> shiftedBits) & ((byte)(1 << bitsToRead) - 1)) << bits;

                this.count += bitsToRead;
            }

            var type = typeof(T).IsEnum ? typeof(T).GetEnumUnderlyingType() : typeof(T);

            return (T)Convert.ChangeType(value, type);
        }

        public string ReadFourCC()
        {
            var data = BitConverter.GetBytes(this.Read<uint>(32));

            Array.Reverse(data);

            return Encoding.UTF8.GetString(data).Trim( '\0' );
        }
        #endregion

        #region Writer
        public void Write<T>(T value)
        {
            var writer = this.stream as BinaryWriter;

            if (writer == null)
                throw new InvalidOperationException("");

            switch (Type.GetTypeCode(typeof(T)))
            {
                case TypeCode.SByte:
                    writer.Write(Convert.ToSByte(value));
                    break;
                case TypeCode.Byte:
                    writer.Write(Convert.ToByte(value));
                    break;
                case TypeCode.Int16:
                    writer.Write(Convert.ToInt16(value));
                    break;
                case TypeCode.UInt16:
                    writer.Write(Convert.ToUInt16(value));
                    break;
                case TypeCode.Int32:
                    writer.Write(Convert.ToInt32(value));
                    break;
                case TypeCode.UInt32:
                    writer.Write(Convert.ToUInt32(value));
                    break;
                case TypeCode.Int64:
                    writer.Write(Convert.ToInt64(value));
                    break;
                case TypeCode.UInt64:
                    writer.Write(Convert.ToUInt64(value));
                    break;
                case TypeCode.Single:
                    writer.Write(Convert.ToSingle(value));
                    break;
                default:
                    if (typeof(T) == typeof(byte[]))
                    {
                        this.Flush();

                        var data = value as byte[];
                        writer.Write(data);
                    }
                    break;
            }
        }

        public void Write<T>(T value, int bits)
        {
            var writer = this.stream as BinaryWriter;

            var bitsToWrite = 0;
            var shiftedBits = 0;

            var unpacked = (ulong)Convert.ChangeType(value, typeof(ulong));
            byte packedByte = 0;

            while (bits != 0)
            {
                shiftedBits = this.count & 7;

                if (shiftedBits != 0 && writer.BaseStream.Length > 0)
                    writer.BaseStream.Position -= 1;

                bitsToWrite = 8 - shiftedBits;

                if (bitsToWrite >= bits)
                    bitsToWrite = bits;

                packedByte = (byte)(this.preByte & ~(ulong)(((1 << bitsToWrite) - 1) << shiftedBits) | (((unpacked >> (bits - bitsToWrite)) & (ulong)((1 << bitsToWrite) - 1)) << shiftedBits));

                this.count += bitsToWrite;
                bits -= bitsToWrite;

                if (shiftedBits != 0)
                    this.preByte = 0;

                this.Write(packedByte);
            }

            this.preByte = packedByte;
        }

        public void Flush()
        {
            var remainingBits = 8 - (this.count & 7);

            if (remainingBits < 8)
                this.Write(0, remainingBits);

            this.preByte = 0;
        }

        public void WriteString(string data, int bits, bool isCString = true, int additionalCount = 0)
        {
            var bytes = Encoding.UTF8.GetBytes(data);

            this.Write(bytes.Length + additionalCount, bits);
            this.Write(bytes);

            if (isCString)
                this.Write(new byte[1]);

            this.Flush();
        }

        public void WriteFourCC(string data)
        {
            var bytes = Encoding.UTF8.GetBytes(data);

            this.Write(bytes);
        }
        #endregion
    }
}
