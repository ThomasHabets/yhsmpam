#!/usr/bin/python
"""YHSMPAM 0.01

Copyright 2011 Google Inc.

YubiHSM for unix authentication.
"""

__author__ = 'Thomas Habets <habets@google.com>'

import pyhsm
import sys
import spwd
import subprocess
import getpass
import os
import re

DEFAULT_KEY_HANDLE = 2
DEFAULT_MIN_LENGTH = 20
DEFAULT_DEVICE='/dev/ttyACM0'
DEFAULT_DATASTORE='/etc/yhsmpam/users/%(username)s'

#
# Exception classes 
#


class Error(Exception):
    pass


class UseError(Error):
    pass

    
class CheckError(Error):
    pass


class CheckDatabaseError(CheckError):
    pass


class CheckMismatchError(CheckError):
    pass


class SetDatabaseError(Error):
    pass


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
        except Exception, e:
            raise Error('pyhsm: ' + str(e))

    def GetUserDatastore(self, user):
        user = user.lower()
        if not user.isalnum():
            raise UseError('Username must be alphanumeric')
        return self.datastore % {'username': user}

    def CheckPassword(self, user, password):
        """CheckPassword(self, user, password) -> None

        Check password with HSM.

        Get user AEAD block and nonce from /etc/shadow, check that
        it's formatted properly and send to HSM.
        """
        f = open(self.GetUserDatastore(user))
        nonce, aead = re.split(r"\s+", f.readline().strip(), 1)
        f.close()

        if not self.hsm.validate_aead(nonce.decode('hex'),
                                      self.key_handle,
                                      aead.decode('hex'),
                                      password.ljust(self.min_length,
                                                     chr(0x0))):
            raise CheckMismatchError("Wrong password according to HSM")

    def SetPassword(self, user, password):
        nonce = self.hsm.get_nonce().nonce
        aead = self.hsm.generate_aead_simple(nonce,
                                             self.key_handle,
                                             password.ljust(self.min_length,
                                                            chr(0x0)))
            
        f = open(self.GetUserDatastore(user), 'w')
        f.write("%s %s\n" % (nonce.encode('hex'), aead.data.encode('hex')))
        f.close()

    def SysInfo(self):
        return self.hsm.info()


class CommandProcessor(object):
    """YubiHSM PAM password command line tool.

    Meant to be run as the main program, but can also be used as a
    library.

    Command line use:
      CommandProcessor.Main(sys.argv)

    Library use:
      cmd = CommandProcessor()
      print cmd.RunCommand('help', ('set',))
      print cmd.RunCommand('set', ('thomas', 'secret'))
    """
    def __init__(self, configfile='/etc/yhsmpam/yhsmpam.conf'):
        super(CommandProcessor, self).__init__()
        self._argv0 = None
        self._commands = {}
        self._configfile = configfile
        self._key_handle = None
        self._device = None
        self._ReadConfig()
        self._hsm = None

        for cmd in [attr for attr in dir(self)
                    if attr.islower()
                    and attr.isalpha()]:
            self._commands[cmd] = self.__getattribute__(cmd)

    @classmethod
    def Main(cls, argv):
        cls.argv0 = argv[0]
        cmd = CommandProcessor()
        try:
            ret = cmd.RunCommand(argv[1], argv[2:])
            if ret:
                print ret
        except UseError, e:
            print e
            cmd.help('help')
            return 1
        except Error, e:
            print >>sys.stderr, "Exception:", type(e)
            if e.args:
                print >>sys.stderr, "Message:  ", e
            return 1

    def _ReadConfig(self):
        self._config = dict([tuple(re.split(r"\s+", line.strip(), 1))
                                   for line in open(self._configfile)])
        for key,val in self._config.iteritems():
            if key in ('key_handle'):
                self.__setattr__('_' + key, int(val))
            elif key in ('device', 'datastore'):
                self.__setattr__('_' + key, val)

    def RunCommand(self, cmd, args):
        return self._commands.get(cmd.lower(), self._UnknownCommand)(cmd,
                                                                     *args)

    def _InitHSM(self):
        if self._hsm is None:
            self._hsm = YHSMPAM(key_handle=self._key_handle,
                                device=self._device,
                                datastore=self._datastore)

    def _UnknownCommand(self, cmd, *args):
        raise UseError("Unknown command: %s" % cmd)

    def _AboutCommand(self, cmd):
        try:
            return ' ' * 8 + self.__getattribute__(cmd.lower()).__doc__
        except AttributeError:
            return "Unknown command: %s" % cmd

    def _Usage(self):
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
        return usagetext

    #
    # Commands below this
    #

    def help(self, cmd, about=None, *args):
        """help                                 Show help text."""

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
        self._InitHSM()
        if password is None:
            password = getpass.getpass('User password: ')
        return self._hsm.SetPassword(username, password)

    def check(self, cmd, username, password=None):
        """check <username> [<password>]        Check user password.

        Example sessions:
            $ sudo yhsmpam set marvin
            User password: <secret>
        """
        self._InitHSM()
        if password is None:
            password = getpass.getpass('User password: ')
        self._hsm.CheckPassword(username, password)
        return "Password correct"

    def sysinfo(self, cmd):
        """sysinfo                              Show YubiHSM system info.

        Example:
            $ sudo yhsmpam sysinfo
            YubiHSM 0.9.8 proto 1 ID 34ff6d063052383032560343
        """
        self._InitHSM()
        info = self._hsm.SysInfo()
        return ("YubiHSM %d.%d.%d proto %d ID %s"
                % (info.version_major,
                   info.version_minor,
                   info.version_build,
                   info.protocol_ver,
                   info.system_uid.encode('hex')))


def PAMHelper():
    user = raw_input("")
    password = raw_input("")
    try:
        hsm = YHSMPAM()
        hsm.CheckPassword(user, password)
        print "OK"
    except Error, e:
        print "FAIL"


def main():
    if len(sys.argv) == 1:
        return PAMHelper()
    else:
        CommandProcessor.Main(sys.argv)

if __name__ == '__main__':
    sys.exit(main())
