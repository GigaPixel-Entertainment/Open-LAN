# Copyright (C) 2026  GigaPixel Entertainment
# Licensed under the GNU General Public License v3, see <https://www.gnu.org/licenses/>.

"""Generate a hash from a provided string"""

import bcrypt
import config

pwdToHash = input("String to hash: ")

hashed = bcrypt.hashpw(pwdToHash.encode("utf-8"), bcrypt.gensalt(config.NUM_ENCRYPT_ROUNDS))

print(f"Hashed: {hashed.decode("utf-8")}")
