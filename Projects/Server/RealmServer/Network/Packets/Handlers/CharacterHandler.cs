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

using RealmServer.Attributes;
using RealmServer.Constants.Net;
using Framework.Network.Packets;

namespace RealmServer.Network.Packets.Handlers
{
    class CharacterHandler
    {
        [Message(ClientMessages.EnumCharacters)]
        public static void OnEnumCharacters(Packet packet, RealmSession session)
        {
            HandleEnumCharactersResult(session);
        }

        public static void HandleEnumCharactersResult(RealmSession session)
        {
            var enumCharactersResult = new Packet(ServerMessages.EnumCharactersResult);

            enumCharactersResult.PutBit(1);
            enumCharactersResult.PutBit(0);

            enumCharactersResult.Flush();

            enumCharactersResult.Write(0);
            enumCharactersResult.Write(0);

            session.Send(enumCharactersResult);
        }

        [Message(ClientMessages.CreateCharacter)]
        public static void OnCreateCharacter(Packet packet, RealmSession session)
        {

        }

        public static void HandleCreateChar(RealmSession session)
        {

        }

        [Message(ClientMessages.CharDelete)]
        public static void OnCharDelete(Packet packet, RealmSession session)
        {

        }

        public static void HandleDeleteChar(RealmSession session)
        {

        }

        [Message(ClientMessages.GenerateRandomCharacterName)]
        public static void OnGenerateRandomCharacterName(Packet packet, RealmSession session)
        {

        }

        public static void HandleGenerateRandomCharacterNameResult(RealmSession session)
        {

        }
    }
}
