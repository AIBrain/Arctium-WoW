﻿/*
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

using System;
using System.Net.Sockets;
using CharacterServer.Constants.Net;
using CharacterServer.Network.Packets;
using CharacterServer.Network.Packets.Handlers;
using Framework.Constants.Misc;
using Framework.Logging;
using Framework.Logging.IO;
using Framework.Misc;
using Framework.Network;
using Framework.Network.Packets;

namespace CharacterServer.Network
{
    class CharacterSession : SessionBase
    {
        public uint Challenge { get; private set; }

        public CharacterSession(Socket clientSocket) : base(clientSocket) { }

        public override void OnConnection(object sender, SocketAsyncEventArgs e)
        {
            if (!isTransferInitiated[1])
            {
                var clientToServer = "WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER";
                var data = new byte[0x32];

                Buffer.BlockCopy(dataBuffer, 0, data, 0, data.Length);

                var transferInitiate = new Packet(data, false);

                var length = transferInitiate.Read<ushort>();
                var msg    = transferInitiate.Read<string>(0, true);

                if (msg == clientToServer)
                {
                    isTransferInitiated[1] = true;

                    e.Completed -= OnConnection;
                    e.Completed += Process;

                    Log.Message(LogType.Debug, "Initial packet transfer for Client '{0}' successfully initialized.", GetClientIP());

                    client.ReceiveAsync(e);

                    // Assign server challenge for auth digest calculations
                    Challenge = BitConverter.ToUInt32(new byte[0].GenerateRandomKey(4), 0);

                    AuthHandler.HandleAuthChallenge(this);
                }
                else
                {
                    Log.Message(LogType.Debug, "Wrong initial packet transfer data for Client '{0}'.", GetClientIP());

                    Dispose();
                }
            }
            else
                Dispose();
        }

        public override void ProcessPacket(Packet packet)
        {
            if (packetQueue.Count > 0)
                packet = packetQueue.Dequeue();

            PacketLog.Write<ClientMessage>(packet.Header.Message, packet.Data, client.RemoteEndPoint);

            PacketManager.InvokeHandler<ClientMessage>(packet, this);
        }

        public override void Send(Packet packet)
        {
            try
            {
                packet.Finish();

                if (packet.Header != null)
                    PacketLog.Write<ServerMessage>(packet.Header.Message, packet.Data, client.RemoteEndPoint);

                if (Crypt != null && Crypt.IsInitialized)
                    Encrypt(packet);

                var socketEventargs = new SocketAsyncEventArgs();

                socketEventargs.SetBuffer(packet.Data, 0, packet.Data.Length);

                socketEventargs.Completed += SendCompleted;
                socketEventargs.UserToken = packet;
                socketEventargs.RemoteEndPoint = client.RemoteEndPoint;
                socketEventargs.SocketFlags = SocketFlags.None;

                client.SendAsync(socketEventargs);
            }
            catch (SocketException ex)
            {
                Log.Message(LogType.Error, "{0}", ex.Message);

                client.Close();
            }
        }

        void SendCompleted(object sender, SocketAsyncEventArgs e)
        {

        }
    }
}
