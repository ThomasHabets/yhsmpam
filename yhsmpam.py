#!/usr/bin/python
# -*- coding: utf-8 -*-
"""YHSMPAM 0.01

YubiHSM for unix authentication.

Author: Thomas Habets <habets@google.com>

Copyright 2011 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

__author__ = 'Thomas Habets <habets@google.com>'

import pyhsm
import sys
import getpass
import re

DEFAULT_KEY_HANDLE = 2
DEFAULT_MIN_LENGTH = 20
DEFAULT_DEVICE = '/dev/ttyACM0'
DEFAULT_DATASTORE = '/etc/yhsmpam/users/%(username)s'

#
# Exception classes 
#


class Error(Exception):
    """Top level exception for this module."""


class UseError(Error):
    """Something wrong with the input."""

    
class CheckError(Error):
    """Error while checking password."""


#
# Main classes
#


class YHSMPAM(object):
    """class YHSMPAM(object):

    Backend class for setting and checking passwords against YubiHSM.

    Example use:
        hsm = YHSMPAM()
        hsm.CheckPassword('thomas', 'secret')
    """
    def __init__(self,
                 device=None,
                 key_handle=None,
                 min_length=None,
                 datastore=None):
        """YHSMPAM.__init__(self, **kwargs)

        Args:
          device:           Device to use (e.g. /dev/ttyACM0)
          key_handle:       YubiHSM key index that encrypts the keys.
          min_length:       Pad passwords to this length.
          datastore:        Directory in which to store users AEAD.
        """
        super(YHSMPAM, self).__init__()

        self.device = device or DEFAULT_DEVICE
        self.key_handle = key_handle or DEFAULT_KEY_HANDLE
        self.min_length = min_length or DEFAULT_MIN_LENGTH
        self.datastore = datastore or DEFAULT_DATASTORE

        try:
            self.hsm = pyhsm.YHSM(self.device)
        except Exception, exc:
            raise Error('pyhsm: ' + str(exc))

    def GetUserDatastore(self, user):
        """GetUserDatastore(self, user) -> str

        Get the full path of the users datastore. Securely.

        Return: full path to users datastore.
        """
        user = user.lower()
        if not user.isalnum():
            raise UseError('Username must be alphanumeric')
        ret = self.datastore % {'username': user}
        if ret[0] != '/':
            raise UseError('User datastore must be absolute path')
        return ret

    def CheckPassword(self, user, password):
        """CheckPassword(self, user, password) -> bool

        Check password with HSM.

        Get user AEAD block and nonce from /etc/shadow, check that
        it's formatted properly and send to HSM.

        Return: True if password is correct.
        """
        fdata = open(self.GetUserDatastore(user))
        nonce, aead = re.split(r"\s+", fdata.readline().strip(), 1)
        fdata.close()

        return self.hsm.validate_aead(nonce.decode('hex'),
                                      self.key_handle,
                                      aead.decode('hex'),
                                      password.ljust(self.min_length,
                                                     chr(0x0)))

    def SetPassword(self, user, password):
        """SetPassword(self, user, password) -> None

        Set user password.
        """
        nonce = self.hsm.get_nonce().nonce
        aead = self.hsm.generate_aead_simple(nonce,
                                             self.key_handle,
                                             password.ljust(self.min_length,
                                                            chr(0x0)))
            
        fdata = open(self.GetUserDatastore(user), 'w')
        fdata.write("%s %s\n" % (nonce.encode('hex'), aead.data.encode('hex')))
        fdata.close()

    def SysInfo(self):
        """Get YubiHSM version info."""
        return self.hsm.info()


class CommandProcessor(object):
    """YubiHSM PAM password command line tool.

    Meant to be run as the main program, but can also be used as a
    library. Unless you call Main() it will not write to stdout/stderr or
    exit().

    Command line use:
      CommandProcessor.Main(sys.argv)

    Library use:
      cmd = CommandProcessor()
      print cmd.RunCommand('help', ('set',))
      print cmd.RunCommand('set', ('thomas', 'secret'))

    To add commands simply create member functions in all lower-case.
    """
    def __init__(self, configfile='/etc/yhsmpam/yhsmpam.conf'):
        super(CommandProcessor, self).__init__()
        self._argv0 = None
        self._hsm = None
        self._configfile = configfile

        # Config
        self._key_handle = None
        self._device = None
        self._datastore = None
        self._ReadConfig()

        self._commands = {}
        for cmd in [attr for attr in dir(self)
                    if attr.islower()
                    and attr.isalpha()]:
            self._commands[cmd] = self.__getattribute__(cmd)

    @classmethod
    def Main(cls, argv):
        """Main(cls, argv) -> int

        main() that should be reusable. Prints to stdout and stderr when
        it feels it's approriate.
        """
        cls.argv0 = argv[0]
        cmd = CommandProcessor()
        try:
            errcode, toprint = cmd.RunCommand(argv[1], argv[2:])
            if toprint:
                print toprint
            return errcode
        except UseError, exc:
            print >> sys.stderr, exc
            cmd.help('help')
        except Error, exc:
            print >> sys.stderr, "Exception:", type(exc)
            if exc.args:
                print >> sys.stderr, "Message:  ", exc
        return 1

    def _ReadConfig(self):
        self._config = dict([tuple(re.split(r"\s+", line.strip(), 1))
                                   for line in open(self._configfile)])
        for key, val in self._config.iteritems():
            if key in ('key_handle'):
                self.__setattr__('_' + key, int(val))
            elif key in ('device', 'datastore'):
                self.__setattr__('_' + key, val)

    def RunCommand(self, cmd, args):
        """RunCommand(self, cmd, args) -> (errcode, str)"""
        return self._commands.get(cmd.lower(), self._UnknownCommand)(cmd,
                                                                     *args)

    def _GetHSM(self):
        """_GetHSM(self) -> hsm

        Init hsm if needed and return it.
        """
        if self._hsm is None:
            self._hsm = YHSMPAM(key_handle=self._key_handle,
                                device=self._device,
                                datastore=self._datastore)
        return self._hsm

    def _UnknownCommand(self, cmd, *args):
        """Callback function for unknown commansd."""
        raise UseError("Unknown command: %s" % cmd)

    def _AboutCommand(self, cmd):
        """_AboutCommand(self, cmd): -> (errcode, str)

        Show detailed help about command.
        """
        try:
            return 0, ' ' * 8 + self._commands[cmd.lower].__doc__
        except KeyError:
            return 1, "Unknown command: %s" % cmd

    def _Usage(self):
        """_Usage(self) -> (errcode, str)

        Return normal usage info.
        """
        usagetext = '''Usage: %s [ <command> ] [ <options> ]

  If no command is given, the script will use PAM mode.

  PAM mode means that it will read two lines from stdin.  The first
  line is the username, the second is the password. If the password
  matches then "OK" is printed. Otherwise it will print "FAIL".

  Commands:
''' % CommandProcessor.argv0
        for cmdname, cmd in sorted(self._commands.items()):
            doc = cmd.__doc__
            usagetext += '    %s\n' % (doc.split('\n')[0])
        return 0, usagetext

    #
    # Commands below this
    #

    def help(self, cmd, about=None, *args):
        """help [<command>]                     Show help text."""

        if about:
            return self._AboutCommand(about)

        return self._Usage()


    def set(self, cmd, username, password=None):
        """set <username> [<password>]          Set new password for user.

        Example sessions:
           $ sudo yhsmpam set thomas
           User password: <secret>
           $
        """
        if password is None:
            password = getpass.getpass('User password: ')
        return 0, self._GetHSM().SetPassword(username, password)

    def check(self, cmd, username, password=None):
        """check <username> [<password>]        Check user password.

        Example sessions:
            $ sudo yhsmpam set marvin
            User password: <secret>
        """
        if password is None:
            password = getpass.getpass('User password: ')
        if self._GetHSM().CheckPassword(username, password):
            return 0, "Password correct"
        else:
            return 1, "Password incorrect"

    def sysinfo(self, cmd):
        """sysinfo                              Show YubiHSM system info.

        Example:
            $ sudo yhsmpam sysinfo
            YubiHSM 0.9.8 proto 1 ID 34ff6d063052383032560343
        """
        info = self._GetHSM().SysInfo()
        return 0, ("YubiHSM %d.%d.%d proto %d ID %s"
                   % (info.version_major,
                      info.version_minor,
                      info.version_build,
                      info.protocol_ver,
                      info.system_uid.encode('hex')))


def PAMHelper():
    """This is the behaviour that pam_externalpass expects."""
    user = raw_input("")
    password = raw_input("")
    hsm = YHSMPAM()
    if hsm.CheckPassword(user, password):
        print "OK"
    else:
        print "FAIL"
    return 0


def main():
    if len(sys.argv) == 1:
        return PAMHelper()
    else:
        return CommandProcessor.Main(sys.argv)


if __name__ == '__main__':
    sys.exit(main())
