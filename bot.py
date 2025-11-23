import json
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from telegram import (
    Update, ReplyKeyboardMarkup, InlineKeyboardMarkup,
    InlineKeyboardButton
)
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, ContextTypes, filters
)

TOKEN =  os.getenv("TOKEN")
DATA_FILE = "passwords.json"
PINS_FILE = "pins.json"

# ---------------- PIN & ENCRYPTION UTILITIES ---------------- #

def load_pins():
    try:
        with open(PINS_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_pins(pins):
    with open(PINS_FILE, "w") as f:
        json.dump(pins, f, indent=4)

def derive_fernet_key(user_id: str, pin: str) -> Fernet:
    """
    Derive a Fernet key from user_id + PIN.
    """
    raw = f"{user_id}:{pin}".encode()
    digest = hashlib.sha256(raw).digest()   # 32 bytes
    key = base64.urlsafe_b64encode(digest)  # Fernet expects base64-encoded 32 bytes
    return Fernet(key)

def set_pin_for_user(user_id: str, pin: str) -> bool:
    """
    Set PIN hash & salt for a user for the first time.
    Returns False if user already has a PIN.
    """
    pins = load_pins()
    if user_id in pins:
        return False

    # Generate salt & hash
    salt_bytes = os.urandom(16)
    salt = base64.urlsafe_b64encode(salt_bytes).decode()
    pin_hash = hashlib.sha256((salt + pin).encode()).hexdigest()

    pins[user_id] = {
        "salt": salt,
        "pin_hash": pin_hash
    }
    save_pins(pins)
    return True

def verify_pin(user_id: str, pin: str) -> bool:
    pins = load_pins()
    info = pins.get(user_id)
    if not info:
        return False

    salt = info["salt"]
    expected = info["pin_hash"]
    actual = hashlib.sha256((salt + pin).encode()).hexdigest()
    return actual == expected

def change_pin_for_user(user_id: str, old_pin: str, new_pin: str) -> bool:
    """
    Change PIN: verify old PIN, then update salt+hash.
    (Encryption re-keying is handled separately in code.)
    """
    if not verify_pin(user_id, old_pin):
        return False

    pins = load_pins()
    salt_bytes = os.urandom(16)
    salt = base64.urlsafe_b64encode(salt_bytes).decode()
    pin_hash = hashlib.sha256((salt + new_pin).encode()).hexdigest()

    pins[user_id] = {
        "salt": salt,
        "pin_hash": pin_hash
    }
    save_pins(pins)
    return True

# ---------------- STORAGE UTILITIES ---------------- #

def load_data():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# ---------------- MENU ---------------- #

async def show_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [["Add", "Update"], ["Delete", "Get All"], ["Show One"]]
    await update.message.reply_text(
        "Choose an option:",
        reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text(
        "Welcome to the 🔐 Password Manager Bot.\n\n"
        "1️⃣ Set a PIN with /setpin\n"
        "2️⃣ Then just use the bot. When you try to view a password, "
        "I'll ask for your PIN and delete that message.\n",
    )
    await show_menu(update, context)

# ---------------- HELP ---------------- #

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📘 *Password Manager Bot Help*\n\n"
        "Your passwords are encrypted with a key derived from your *PIN + Telegram ID*.\n"
        "The PIN itself is never stored, only a salted hash.\n\n"
        "🔑 *First-time setup:*\n"
        "1. Send `/setpin` – I'll ask you to send your new PIN in the next message.\n"
        "2. After that, your vault is unlocked.\n\n"
        "🔐 *Daily usage:*\n"
        "- Use /add, /update, /delete, /getall, /showone as usual.\n"
        "- If the vault is locked when you try to view a password, I will ask for your PIN.\n"
        "- You send the PIN, I delete that message and show your data.\n\n"
        "🔁 *Changing your PIN:*\n"
        "- Send `/changepin` – I'll first ask for your OLD PIN.\n"
        "- If it’s correct, I’ll ask for your NEW PIN.\n"
        "- Your whole vault will be re-encrypted with the new PIN key.\n\n"
        "You can also manually unlock with `/unlock` if you want.\n"
        "⚠️ If you forget your PIN, your vault cannot be decrypted.\n",
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

# ---------------- PIN COMMANDS ---------------- #

async def cmd_setpin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.message.from_user.id)
    pins = load_pins()
    if user_id in pins:
        await update.message.reply_text(
            "You already have a PIN. Use /changepin to change it."
        )
        return

    # interactive mode: next message will be the PIN
    context.user_data["mode"] = "set_pin"
    await update.message.reply_text(
        "Send your new PIN now (it can be any text).\n"
        "I will delete this message after I use it."
    )

async def cmd_unlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Ask for PIN interactively
    context.user_data["mode"] = "unlock_pin"
    context.user_data["pending_action"] = None
    await update.message.reply_text(
        "Send your PIN to unlock the vault.\n"
        "I will delete your PIN message."
    )

async def cmd_changepin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.message.from_user.id)
    pins = load_pins()
    if user_id not in pins:
        await update.message.reply_text(
            "You don't have a PIN yet. Use /setpin first."
        )
        return

    # interactive flow: ask for old PIN first
    context.user_data["mode"] = "changepin_old"
    await update.message.reply_text(
        "Send your OLD PIN.\nI will delete this message."
    )

# ---------------- SLASH COMMANDS THAT USE REGULAR FLOW ---------------- #

async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["mode"] = "add_pair_name"
    await update.message.reply_text("Send NAME for the pair (e.g. Facebook, Gmail, YouTube):")

async def cmd_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await handle_message(update, context)

async def cmd_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await handle_message(update, context)

async def cmd_getall(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await handle_message(update, context)

async def cmd_showone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await handle_message(update, context)

# ---------------- MESSAGE HANDLER ---------------- #

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    lower = text.lower()
    user_id = str(update.message.from_user.id)
    chat_id = update.effective_chat.id
    msg_id = update.message.message_id

    data = load_data()
    if user_id not in data:
        data[user_id] = {}

    mode = context.user_data.get("mode")

    # ---------- HANDLE SET PIN MODE ----------
    if mode == "set_pin":
        pin = text

        # delete the PIN message for privacy
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
        except Exception:
            pass

        success = set_pin_for_user(user_id, pin)
        if not success:
            context.user_data["mode"] = None
            await update.effective_chat.send_message(
                "You already have a PIN. Use /changepin to change it."
            )
            return

        fernet = derive_fernet_key(user_id, pin)
        context.user_data["unlocked"] = True
        context.user_data["fernet"] = fernet
        context.user_data["mode"] = None
        await update.effective_chat.send_message(
            "✅ PIN set successfully.\n🔓 Vault unlocked."
        )
        return

    # ---------- HANDLE UNLOCK-PIN MODE ----------
    if mode == "unlock_pin":
        pin = text

        # delete the PIN message
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
        except Exception:
            pass

        if not verify_pin(user_id, pin):
            context.user_data["mode"] = None
            context.user_data["pending_action"] = None
            await update.effective_chat.send_message("❌ Wrong PIN.")
            return

        fernet = derive_fernet_key(user_id, pin)
        context.user_data["unlocked"] = True
        context.user_data["fernet"] = fernet

        pending = context.user_data.get("pending_action")
        context.user_data["mode"] = None
        context.user_data["pending_action"] = None

        if pending and pending.get("type") == "show":
            pair_name = pending["pair_name"]
            entry = data[user_id][pair_name]
            dec_login = fernet.decrypt(entry["login"].encode()).decode()
            dec_password = fernet.decrypt(entry["password"].encode()).decode()
            await update.effective_chat.send_message(
                f"Name: {pair_name}\n"
                f"Login: {dec_login}\n"
                f"Password: {dec_password}"
            )
        else:
            await update.effective_chat.send_message("🔓 Vault unlocked.")
        return

    # ---------- CHANGE PIN: ENTER OLD PIN ----------
    if mode == "changepin_old":
        old_pin = text.strip()

        # delete old PIN message
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
        except Exception:
            pass

        if not verify_pin(user_id, old_pin):
            context.user_data.clear()
            await update.effective_chat.send_message("❌ Old PIN is incorrect.")
            return

        # Store old pin and ask for new pin
        context.user_data["changepin_old_pin"] = old_pin
        context.user_data["mode"] = "changepin_new"
        await update.effective_chat.send_message(
            "Old PIN verified.\nNow send your NEW PIN.\nI will delete it as well."
        )
        return

    # ---------- CHANGE PIN: ENTER NEW PIN ----------
    if mode == "changepin_new":
        new_pin = text.strip()

        # delete new PIN message
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
        except Exception:
            pass

        old_pin = context.user_data.get("changepin_old_pin")

        # Re-encrypt all entries with new key
        data = load_data()
        user_entries = data.get(user_id, {})

        old_fernet = derive_fernet_key(user_id, old_pin)
        new_fernet = derive_fernet_key(user_id, new_pin)

        for name, entry in user_entries.items():
            try:
                dec_login = old_fernet.decrypt(entry["login"].encode()).decode()
                dec_pass = old_fernet.decrypt(entry["password"].encode()).decode()
            except Exception:
                continue

            entry["login"] = new_fernet.encrypt(dec_login.encode()).decode()
            entry["password"] = new_fernet.encrypt(dec_pass.encode()).decode()

        data[user_id] = user_entries
        save_data(data)

        # Update PIN hash
        change_pin_for_user(user_id, old_pin, new_pin)

        # Unlock with new PIN
        context.user_data.clear()
        context.user_data["unlocked"] = True
        context.user_data["fernet"] = new_fernet

        await update.effective_chat.send_message("✅ PIN changed successfully!")
        return

    # ---------- REQUIRE UNLOCK FOR OTHER OPS ----------
    if not context.user_data.get("unlocked") or "fernet" not in context.user_data:
        await update.message.reply_text(
            "🔒 Vault is locked. Use /unlock or try again and I'll ask for your PIN."
        )
        return

    fernet: Fernet = context.user_data["fernet"]

    # ---------------- ADD MODE ----------------
    if mode == "add_pair_name":
        context.user_data["pair_name"] = text
        context.user_data["mode"] = "add_login"
        await update.message.reply_text("Send LOGIN (email or username):")
        return

    if mode == "add_login":
        context.user_data["login"] = text
        context.user_data["mode"] = "add_password"
        await update.message.reply_text("Send PASSWORD:")
        return

    if mode == "add_password":
        pair = context.user_data["pair_name"]
        login_val = context.user_data["login"]
        password_val = text

        enc_login = fernet.encrypt(login_val.encode()).decode()
        enc_password = fernet.encrypt(password_val.encode()).decode()

        data[user_id][pair] = {
            "login": enc_login,
            "password": enc_password
        }

        save_data(data)
        context.user_data.clear()

        await update.message.reply_text(f"Saved: {pair}")
        await show_menu(update, context)
        return

    # ---------------- UPDATE PASSWORD MODE ----------------
    if mode == "update_password":
        pair = context.user_data["login_to_update"]
        new_pass = text
        enc_password = fernet.encrypt(new_pass.encode()).decode()

        data[user_id][pair]["password"] = enc_password
        save_data(data)
        context.user_data.clear()

        await update.message.reply_text(f"Password updated for: {pair}")
        await show_menu(update, context)
        return

    # ---------------- ADD COMMAND AS TEXT ----------------
    if lower in ["add", "/add"]:
        context.user_data["mode"] = "add_pair_name"
        await update.message.reply_text("Send NAME for the pair (e.g. Facebook, Gmail, YouTube):")
        return

    # ---------------- UPDATE ----------------
    if lower in ["update", "/update"]:
        names = list(data[user_id].keys())
        if not names:
            await update.message.reply_text("No saved entries.")
            return

        buttons = [[InlineKeyboardButton(n, callback_data=f"update:{n}")] for n in names]

        await update.message.reply_text(
            "Choose entry to update password:",
            reply_markup=InlineKeyboardMarkup(buttons)
        )
        return

    # ---------------- DELETE ----------------
    if lower in ["delete", "/delete"]:
        names = list(data[user_id].keys())
        if not names:
            await update.message.reply_text("Nothing to delete.")
            return

        buttons = [[InlineKeyboardButton(n, callback_data=f"delete:{n}")] for n in names]

        await update.message.reply_text(
            "Choose entry to delete:",
            reply_markup=InlineKeyboardMarkup(buttons)
        )
        return

    # ---------------- GET ALL ----------------
    if lower in ["get all", "/getall"]:
        names = list(data[user_id].keys())
        if not names:
            await update.message.reply_text("No saved entries.")
        else:
            await update.message.reply_text("Saved names:\n" + "\n".join(names))

        await show_menu(update, context)
        return

    # ---------------- SHOW ONE ----------------
    if lower in ["show one", "/showone"]:
        names = list(data[user_id].keys())
        if not names:
            await update.message.reply_text("No saved entries.")
            return

        buttons = [[InlineKeyboardButton(n, callback_data=f"show:{n}")] for n in names]

        await update.message.reply_text(
            "Choose entry to show:",
            reply_markup=InlineKeyboardMarkup(buttons)
        )
        return

# ---------------- CALLBACK HANDLER ---------------- #

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    user_id = str(query.from_user.id)
    data = load_data()
    action, pair_name = query.data.split(":")

    # If locked and user wants to SHOW, ask for PIN and remember action
    if (not context.user_data.get("unlocked") or "fernet" not in context.user_data) and action == "show":
        context.user_data["mode"] = "unlock_pin"
        context.user_data["pending_action"] = {"type": "show", "pair_name": pair_name}
        await query.edit_message_text(
            "🔒 Vault is locked. Please send your PIN.\n"
            "I will delete your PIN message."
        )
        return

    # For other actions while locked, just block
    if not context.user_data.get("unlocked") or "fernet" not in context.user_data:
        await query.edit_message_text("🔒 Vault is locked. Use /unlock first.")
        return

    fernet: Fernet = context.user_data["fernet"]

    # DELETE
    if action == "delete":
        del data[user_id][pair_name]
        save_data(data)
        await query.edit_message_text(f"Deleted: {pair_name}")
        return

    # SHOW (unlocked)
    if action == "show":
        entry = data[user_id][pair_name]
        dec_login = fernet.decrypt(entry["login"].encode()).decode()
        dec_password = fernet.decrypt(entry["password"].encode()).decode()

        await query.edit_message_text(
            f"Name: {pair_name}\n"
            f"Login: {dec_login}\n"
            f"Password: {dec_password}"
        )
        return

    # UPDATE
    if action == "update":
        context.user_data["mode"] = "update_password"
        context.user_data["login_to_update"] = pair_name
        await query.edit_message_text(
            f"Send new PASSWORD for {pair_name}:"
        )
        return

# ---------------- MAIN ---------------- #

def main():
    app = ApplicationBuilder().token(TOKEN).build()

    # PIN-related commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("setpin", cmd_setpin))
    app.add_handler(CommandHandler("unlock", cmd_unlock))
    app.add_handler(CommandHandler("changepin", cmd_changepin))

    # Vault commands
    app.add_handler(CommandHandler("add", cmd_add))
    app.add_handler(CommandHandler("update", cmd_update))
    app.add_handler(CommandHandler("delete", cmd_delete))
    app.add_handler(CommandHandler("getall", cmd_getall))
    app.add_handler(CommandHandler("showone", cmd_showone))

    # Text handler
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Callback handler
    app.add_handler(CallbackQueryHandler(callback_handler))

    print("PIN-encrypted Password Bot started...")
    app.run_polling()

if __name__ == "__main__":
    main()
