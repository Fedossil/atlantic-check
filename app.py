import hashlib
import json
import re
import zipfile
from enum import Enum
from io import BytesIO
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AtlanticCheck API", version="2.0.0")

MAX_FILES = 300
MAX_TOTAL_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_INNER_ENTRIES = 2000

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Status(str, Enum):
    ALLOWED = "ALLOWED"
    BANNED = "BANNED"
    SUSPICIOUS = "SUSPICIOUS"

class ModScanResult(BaseModel):
    filename: str
    status: Status
    name: str
    reason: str
    punishment: Optional[str] = None
    hash: str

# =========================================================================
# 1. ГЛУБОКИЕ СИГНАТУРЫ ЧИТОВ И СКРЫТЫХ ИНЖЕКТОВ
# =========================================================================
RAW_DEEP_BANNED = [
    (r"invmove|inventorywalk|movementingui|movement_in_gui|me/pieking1215/invmove",
     "InvMove", "Бан 5 дней", "Передвижение и прыжки с открытым инвентарём/меню"),
    (r"(replaceable_x_ray|bizcub|\bx_ray\b|net/minecraft/xray)",
     "X-Ray Mod", "Бан 28 дней", "Рентген руд и блоков / поиск ресурсов"),
    (r"(^|[/\._])baritone([/\._]|$)", "Baritone", "Бан 28 дней", "Автоматизированный бот"),
    (r"(^|[/\._])fabriton([/\._]|$)", "Fabriton", "Бан 28 дней", "Автоматизированный бот"),
    (r"(^|[/\._])meteor([/\._]|$)", "Meteor Client", "Бан 28 дней", "Чит-клиент"),
    (r"(^|[/\._])expensive([/\._]|$)", "Expensive Client", "Бан 28 дней", "Чит-клиент"),
    (r"(^|[/\._])celestial([/\._]|$)", "Celestial Client", "Бан 28 дней", "Чит-клиент"),
    (r"(^|[/\._])wexside([/\._]|$)", "Wexside Client", "Бан 28 дней", "Чит-клиент"),
    (r"(^|[/\._])deadcode([/\._]|$)", "DeadCode", "Бан 28 дней", "Чит-клиент"),
    (r"(^|[/\._])nurik([/\._]|$)|nursultan", "Nurik / Nursultan", "Бан 28 дней", "Чит-клиент"),
    (r"(^|[/\._])vape([/\._]|$)", "Vape Client", "Бан 28 дней", "Чит-клиент"),
    (r"(^|[/\._])thunderhack([/\._]|$)", "ThunderHack", "Бан 28 дней", "Чит-клиент")
]

# =========================================================================
# 2. СПИСОК ЗАПРЕЩЁННЫХ МОДИФИКАЦИЙ (ПО РЕГЛАМЕНТУ)
# =========================================================================
RAW_TARGETED_BANNED = [
    # --- 3 дня ---
    (r"\b(armorhotswap|armor_hot_swap)\b", "ArmorHotSwap", "Бан 3 дня", "Быстрая автоматическая смена элементов брони"),
    (r"\b(elytraswap|elytra_swap)\b(?!.*jjelytraswap)", "ElytraSwap", "Бан 3 дня", "Автоматическая смена нагрудника на элитры"),
    (r"\b(stackrefill|stack_refill)\b", "StackRefill", "Бан 3 дня", "Автоматическое пополнение предметов в хотбаре"),

    # --- 5 дней ---
    (r"\b(accurateblockplacement|accurate_block_placement)\b", "Accurate Block Placement", "Бан 5 дней", "Упрощённая/автоматизированная установка блоков без задержек"),
    (r"\b(autosprint|auto_sprint|autosprintmod)\b", "Auto Sprintmod", "Бан 5 дней", "Автоматический бег/спринт в обход стандартной механики"),
    (r"\b(chesttracker|chest_tracker)\b", "ChestTracker", "Бан 5 дней", "Отслеживание и запоминание содержимого сундуков"),
    (r"\b(easyplaceshulkersupply|easyplaceshulker)\b", "EasyPlaceShulker Supply", "Бан 5 дней", "Автоматическое извлечение ресурсов из шалкеров при стройке"),
    (r"\b(fasterladderclimbing|faster_ladder_climbing)\b", "FasterLadderClimbing", "Бан 5 дней", "Увеличение скорости подъёма по лестницам"),
    (r"\b(inventorycontroltweaks|inventory_control_tweaks)\b", "InventoryControlTweaks", "Бан 5 дней", "Чит-контроль слотов"),
    (r"\b(foodslot|food_slot)\b", "Foodslot", "Бан 5 дней", "Авто-еда в PvP слотах"),
    (r"\b(quickstack|quick_stack)\b", "Quickstack", "Бан 5 дней", "Быстрый стак"),
    (r"\b(itemswap|item_swap)\b", "ItemSwap", "Бан 5 дней", "Авто-свап предметов"),
    (r"\b(autotool|auto_tool)\b", "AutoTool", "Бан 5 дней", "Авто-выбор инструментов"),
    (r"\b(fasterblockplacement|faster_block_placement)\b", "FasterBlockPlacement", "Бан 5 дней", "Ускоренная установка блоков"),
    (r"\b(fireworkhelper|firework_helper)\b", "Firework Helper", "Бан 5 дней", "Авто-фейерверки"),

    # --- 7 дней ---
    (r"\breacharound\b", "Reacharound", "Бан 7 дней", "Установка блоков перед собой без наведения на грань (Bridging)"),

    # --- 10 дней ---
    (r"(^|[/\._\-])bobby([/\._\-]|$)", "Bobby", "Бан 10 дней", "Кэширование и рендер чанков сверх лимита сервера"),
    (r"\b(cleancut|clean_cut)\b", "CleanCut", "Бан 10 дней", "Атака сущностей сквозь траву, кусты и растительность"),
    (r"\b(distanthorizons|distant_horizons)\b", "Distant Horizons", "Бан 10 дней", "LOD-рендеринг мира на экстремальные дистанции"),
    (r"\b(fastexp|fast_exp)\b", "FastExp", "Бан 10 дней", "Ускоренный сбор сфер опыта"),
    (r"\b(goprone|go_prone)\b", "GoProne", "Бан 10 дней", "Принудительное положение лёжа (пролаз в 1 блок)"),
    (r"\b(grassbypass|grass_bypass)\b", "Grass Bypass", "Бан 10 дней", "Игнорирование хитбоксов травы при взаимодействии с миром"),
    (r"\b(autocasino|auto_casino|topkacasino|topka_casino)\b", "TopkaCasino", "Бан 10 дней", "Модификация с запрещённым функционалом"),
    (r"(^|[/\._\-])neat([/\._\-]|$)", "Neat", "Бан 10 дней", "ESP отображение здоровья мобов/игроков"),
    (r"\b(chunkanimator|chunk_animator)\b", "ChunkAnimator", "Бан 10 дней", "Просвечивание сквозь анимацию чанков"),
    (r"\b(mobhealthbar|mob_health_bar)\b", "MobHealthBar", "Бан 10 дней", "ХП-бары сквозь препятствия"),
    (r"\b(blockentitytooltip|block_entity_tooltip)\b", "Block-Entity-Tooltip", "Бан 10 дней", "Просмотр содержимого закрытых контейнеров"),
    (r"\b(cooldownshud|usetracker|use_tracker)\b", "Cooldowns HUD / UseTracker", "Бан 10 дней", "Отслеживание кулдаунов противников"),
    (r"\b(removeblindness|remove_blindness)\b", "RemoveBlindness", "Бан 10 дней", "Отключение слепоты"),
    (r"\b(nodarknesseffect|removewardeneffect|no_darkness_effect)\b", "No Darkness Effect", "Бан 10 дней", "Отключение эффекта тьмы"),
    (r"\b(donthitteammates|dont_hit_teammates)\b", "Dont Hit Teammates", "Бан 10 дней", "Фильтр союзников в PvP"),
    (r"\b(autojumpreset|auto_jump_reset)\b", "AutoJumpReset", "Бан 10 дней", "Сброс кулдауна прыжков в PvP"),
    (r"fevervisuals", "FeverVisuals", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"(^|[/\._\-])ascart([/\._\-]|$)", "Ascart", "Бан 10 дней", "Запрещённый клиент"),
    (r"simplevisuals", "SimpleVisuals", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"wavevisuals", "WaveVisuals", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"(^|[/\._\-])clientcommands([/\._\-]|$)", "ClientCommands", "Бан 10 дней", "Запрещённый пакет команд"),
    (r"phantomvisual(?!s)", "Phantom Visual", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"shinyvisuals", "Shiny Visuals", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"pvpessentialsrefined", "PVP essentials Refined", "Бан 10 дней", "Запрещённый PvP-пак"),
    (r"zero\s*visuals|zerovisuals", "Zero Visuals", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"more\s*visuals|morevisuals", "More Visuals", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"pvputils|pvp_utils", "PVPUtils", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"visual\+|visualplus", "Visual+", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"k3d\s*visuals|k3dvisuals", "K3d Visuals", "Бан 10 дней", "Запрещённый визуал-пак"),
    (r"enough\s*visuals|enoughvisuals", "Enough Visuals", "Бан 10 дней", "Запрещённый визуал-пак"),

    # --- 14 дней ---
    (r"\b(combatroll|combat_roll)\b", "Combat Roll", "Бан 14 дней", "Кувырки и уклонения, меняющие механику движения в PvP"),
    (r"\b(easybuilding|easy_building)\b", "EasyBuilding", "Бан 14 дней", "Автоматическое быстрое размещение блоков и построек"),
    (r"\b(effortlessbuilding|effortless_building)\b", "Effortless Building", "Бан 14 дней", "Симметричное и массовое возведение структур"),
    (r"\b(schematicaprinter|litematicaprinter)\b", "Litematica Printer", "Бан 14 дней", "Автоматический принтер схематик без участия игрока"),
    (r"\b(xaeroplus|xaero_plus)\b", "XaeroPlus", "Бан 14 дней", "Расширенный функционал карты (ESP, радар, повышенная дальность)"),
    (r"\b(truesight|true_sight)\b", "TrueSight", "Бан 14 дней", "Подсветка невидимых игроков"),
    (r"\b(friendhighlighter|friend_highlighter)\b", "Friend Highlighter", "Бан 14 дней", "Подсветка сквозь стены"),
    (r"\b(playerspotlight|player_spotlight)\b", "Player Spotlight", "Бан 14 дней", "ESP подсветка игроков"),
    (r"\b(auchelper|auc_helper)\b", "AucHelper", "Бан 14 дней", "Парсер/бот аукциона"),
    (r"\b(donutauctions|donut_auctions)\b", "Donut Auctions", "Бан 14 дней", "Бот/хелпер аукциона"),
    (r"\b(betterpvp|better_pvp)\b", "Better PVP", "Бан 14 дней", "Комплексный PvP-чит функционал"),
    (r"\b(reentityoutline|re_entity_outline)\b", "Re:Entity Outline", "Бан 14 дней", "Подсветка контуров сквозь стены"),
    (r"\b(antiinvis|anti_invis)\b", "AntiInvis", "Бан 14 дней", "Отключение эффекта невидимости"),
    (r"\b(cheatutils|cheat_utils)\b", "CheatUtils", "Бан 14 дней", "Набор читерских утилит"),
    (r"\b(autoleave|auto_leave)\b", "AutoLeave", "Бан 14 дней", "Авто-выход при опасности"),
    (r"\b(replaymod|replay_mod)\b", "ReplayMod", "Бан 14 дней", "Запись игры без согласования"),
    (r"\b(isometricrender|isometric_render)\b", "IsometricRender", "Бан 14 дней", "Рендер карты"),
    (r"\b(cmdcam|cmd_cam)\b", "CmdCam", "Бан 14 дней", "Управление камерой"),
    (r"\bflashback\b", "Flashback", "Бан 14 дней", "Запись и реплей без разрешения"),

    # --- 18 дней ---
    (r"\b(stepup|step_up|stepupmod)\b", "StepUp Mod", "Бан 18 дней", "Автоматический шаг на возвышенность без прыжка"),
    (r"\b(autoattack|auto_attack)\b", "AutoAttack", "Бан 18 дней", "Авто-атака"),
    (r"\b(autoaim|auto_aim)\b", "AutoAim", "Бан 18 дней", "Авто-наводка"),
    (r"(^|[/\._\-])inventoryprofilesnext([/\._\-]|$)", "Inventory Profiles Next", "Бан 18 дней", "Авто-сортировка инвентаря"),

    # --- 28 дней ---
    (r"\b(autocrystal|auto_crystal)\b", "AutoCrystal", "Бан 28 дней", "Автоматическая установка и подрыв кристаллов края"),
    (r"\b(autofish|auto_fish|xplusautofish)\b", "AutoFish", "Бан 28 дней", "Автоматическая рыбалка в AFK-режиме"),
    (r"\b(femalegender|female_gender|femalegendermod)\b", "Female Gender Mod", "Бан 28 дней", "Запрещённая клиентская модификация моделей"),
    (r"\b(inventorytotem|inventory_totem)\b", "Inventory Totem", "Бан 28 дней", "Автоматическое взятие тотема в руку перед смертью"),
    (r"\b(seedcracker|seed_cracker|seedcrackerx)\b", "SeedCrackerX", "Бан 28 дней", "Взлом и вычисление сида (генерации) мира сервера"),
    (r"\b(shulkeropener|shulker_opener|openinv|open_inv)\b", "ShulkerOpener / OpenInv", "Бан 28 дней", "Открытие шалкера/инвентаря без установки или разрешения"),
    (r"\b(slippery|slipperymod)\b", "Slippery Mod", "Бан 28 дней", "Модификация физики скольжения и передвижения"),
    (r"\btweakeroo\b", "Tweakeroo", "Бан 28 дней", "Чит-твики (FreeCam, FastBlockPlacement, FlexiblePlacement и др.)"),
    (r"\b(walljump|wall_jump|walljumptxf)\b", "Wall-Jump TXF", "Бан 28 дней", "Прыжки и отталкивание от стен"),
    (r"\b(worlddownloader|world_downloader|wdl)\b", "WorldDownloader", "Бан 28 дней", "Скачивание карты и структур сервера"),
    (r"(^|[/\._\-])(worldedit|worldeditcui)([/\._\-]|$)", "WorldEdit", "Бан 28 дней", "Инструменты редактирования мира"),
    (r"\b(automining|auto_mining)\b", "AutoMining", "Бан 28 дней", "Автоматическое копание"),
    (r"\b(replantingcrops|replanting_crops)\b", "ReplantingCrops", "Бан 28 дней", "Авто-посадка урожая"),
    (r"\b(autoharvest|auto_harvest)\b", "AutoHarvest", "Бан 28 дней", "Авто-сбор урожая"),
    (r"(^|[/\._\-])reap([/\._\-]|$)", "Reap", "Бан 28 дней", "Автоматическая рубка/сбор"),
    (r"\b(clickcrystal|click_crystal)\b", "ClickCrystal", "Бан 28 дней", "Макросы и кристал-боты"),
    (r"\b(autoclicky|auto_clicky)\b", "AutoClicky", "Бан 28 дней", "Запрещённый автокликер"),
    (r"\b(autobuy|auto_buy)\b", "AutoBuy", "Бан 28 дней", "Авто-скупка на аукционе"),
    (r"\b(autosell|auto_sell)\b", "AutoSell", "Бан 28 дней", "Авто-продажа на аукционе"),
    (r"\b(autopilot|auto_pilot)\b", "AutoPilot", "Бан 28 дней", "Автопилот"),
    (r"\b(diamondgen|diamond_gen|diamondsim)\b", "DiamondGen", "Бан 28 дней", "Поиск алмазов и генераций"),
    (r"\b(basefinder|base_finder)\b", "BaseFinder", "Бан 28 дней", "Поиск баз игроков сквозь чанки"),
    (r"\b(chestlocator|chest_locator|chestesp|spawnerlocator)\b", "Chest Locator / ESP", "Бан 28 дней", "Поиск сундуков и спавнеров сквозь стены"),
    (r"\b(entityxray|playerxray|entityoutliner|playerhighlighter)\b", "Entity / Player X-Ray", "Бан 28 дней", "Подсветка и рентген сущностей"),
    (r"\b(noclipflymod|noclipfly)\b", "NoclipFlyMod", "Бан 28 дней", "Чит-полёт сквозь блоки"),
    (r"\b(automaceswap|nojumpdelay|aimassistance|autolook)\b", "Combat Cheats", "Бан 28 дней", "Боевые чит-модификации"),
    (r"(^|[/\._\-])(xray|x-ray|x_ray)([/\._\-]|$)", "X-Ray Mod", "Бан 28 дней", "Рентген руд и блоков / поиск ресурсов"),
    (r"\bfreecam\b(?!.*(replay|compat))", "FreeCam", "Бан 28 дней", "Свободная камера сквозь блоки")
]

# Предварительная компиляция регулярных выражений
DEEP_BANNED_COMPILED = [(re.compile(p, re.IGNORECASE), name, dur, rsn) for p, name, dur, rsn in RAW_DEEP_BANNED]
TARGETED_BANNED_COMPILED = [(re.compile(p, re.IGNORECASE), name, dur, rsn) for p, name, dur, rsn in RAW_TARGETED_BANNED]

# =========================================================================
# 3. БЕЛЫЙ СПИСОК (UNDETECT)
# =========================================================================
ALLOWED_WHITELIST_RAW = {
    # Сетевые и чат-патчи
    "viafabricplus", "viafabric", "viabackwards", "viaversion",
    "chatpatches", "chat_patches", "chat-patches",

    # QoL, Твики интерфейса и управление
    "betteradvancements", "better_advancements", "better-advancements",
    "bettermounthud", "better_mount_hud", "better-mount-hud",
    "betterstats", "better_statistics_screen", "betterstatisticsscreen",
    "borderlessfullscreen", "borderless_fullscreen", "borderless-fullscreen",
    "borderless", "borderlessmining", "borderless_mining", "borderless-mining",
    "clienttweaks", "client_tweaks", "client-tweaks",
    "commandkeys", "command_keys", "command-keys",
    "cwb", "cubeswithoutborders", "cubes_without_borders", "cubes-without-borders",
    "debugify", "defaultoptions", "default_options", "default-options",
    "healthindicators", "health_indicators", "health-indicators",
    "keybindspurger", "keybinds_purger", "keybinds-purger",
    "modelfix", "modelgapfix", "model_gap_fix", "model-gap-fix",
    "no-peeking", "nopeeking", "no_peeking", "noxesium",
    "particle_core", "particlecore", "particle-core",
    "placeholder-api", "placeholder_api", "placeholderapi",
    "prickle", "pricklemc", "resourcefulconfig", "resourceful_config", "resourceful-config",
    "rrls", "removereloadingscreen", "remove_reloading_screen", "remove-reloading-screen",
    "satin", "scoreboardtweaks", "scoreboard_tweaks", "scoreboard-tweaks",
    "shieldfixes", "shield_fixes", "shield-fixes", "shieldstatusmod", "shield_status_mod", "shield-status-mod",
    "skyboxify", "smoothskies", "smooth_skies", "smooth-skies",
    "sodium-shadowy-path-blocks", "sodium_shadowy_path_blocks", "sodiumshadowypathblocks",
    "shadowypathblocks", "shadowy_path_blocks", "shadowy-path-blocks",
    "tcdcommons", "tcdcommonsapi", "tcd_commons_api", "tcd-commons-api",
    "titlefixer", "title_fixer", "title-fixer", "titletweaks", "title_tweaks", "title-tweaks",
    "ukulib", "uku3lig", "visualkeys", "visual_keys", "visual-keys",
    "walksylib", "walksy_lib", "walksy-lib", "yet_another_config_lib_v3",
    "yet_another_config_lib", "yacl", "yetanotherconfiglib",
    "anvianslib", "anvians_lib", "anvians-lib", "attributefix", "attribute_fix", "attribute-fix",

    # Авторизация, голос, зум
    "voicechat", "simple-voice-chat", "simple_voice_chat", "plasmovoice", "plasmo-voice",
    "authmemask", "authme-login-mask", "authme_login_mask", "authme", "authme-fabric",
    "zoomify", "logical_zoom", "ok_zoomer", "wi_zoom", "simple_zoom", "zoom", "spytf", "cinematiccam",
    "amecs", "amecs-api", "betterhurtcam", "hurtcam", "nohurtcam", "camerautils",
    "mouse-tweaks", "mousetweaks", "controlling", "keybind-fix", "searchables",

    # Оптимизация
    "sodium", "rubidium", "embeddium", "iris", "oculus", "lithium", "radium", "canary",
    "ferritecore", "entityculling", "immediatelyfast", "indium", "krypton", "lazydfu",
    "c2me", "smoothboot", "fastload", "memoryleakfix", "modernfix", "nvidium", "dynamic_fps",
    "dynamicfps", "vulkanmod", "exitleag", "exitlag", "betterhitreg", "dashloader",
    "enhancedblockentities", "fastopenlinksandfolders", "fastbench", "fastfurnace",
    "fastsuite", "noisium", "chunk-sending", "vmp", "spark", "observable",
    "packet-fixer", "packetfixer", "chunky", "fastpaintings", "servercore", "moreculling",
    "threadtweak", "hydrogen", "sodium-extra", "reeses-sodium-options", "entity-collision-fps-fix",
    "entityviewdistancetoggle", "fastquit", "language-reload", "fabrishot", "badoptimizations", "exordium",

    # Библиотеки ядра
    "fabric-api", "fabric_api", "fabric-language-kotlin", "fabric-language-scala",
    "quilted_fabric_api", "architectury", "cloth-config", "cloth_config", "cloth-config2",
    "forgeconfigapiport", "curios", "trinkets", "geckolib", "player-animation-lib",
    "creativecore", "iceberg", "puzzleslib", "balm", "collective", "fzzy_config",
    "midnightlib", "spruceui", "oow", "owo-lib", "cardinal-components",
    "cardinal-components-base", "cca", "modmenu", "prism", "bclib", "patchouli",
    "citresewn", "continuity", "animatica", "puzzle", "culllessleaves",
    "cull-less-leaves", "connectormod", "sinytra-connector", "mixinextras",

    # HUD, Инвентарь, Миникарты
    "appleskin", "shulkerboxtooltip", "jei", "justenoughitems", "rei", "roughlyenoughitems",
    "emi", "wthit", "jade", "theoneprobe", "minihud", "inventoryhud", "inventory_hud",
    "durabilityviewer", "giselbaer", "armorhud", "status-effect-bars", "betterf3",
    "itemscroller", "inventorycleaner", "jjelytraswap", "containersearcher", "itemlocks",
    "topkatags", "topkahealth", "zakohealthindicator", "berdinskiybear",
    "xaeros_minimap", "xaerominimap", "xaeros_world_map", "xaeroworldmap",
    "journeymap", "voxelmap", "cherishedworlds", "betterpingdisplay", "ping-wheel",
    "chat_heads", "chatheads", "customcrosshair", "fullbright", "blur", "motionblur",
    "cameraoverhaul", "tooltipfix", "chat-up", "compact-chat", "talk-bubbles", "raised",
    "bedrockifysupport", "bedrockify", "custom-skin-loader", "customskinloader",
    "skinlayers3d", "3dskinlayers", "waveycapes", "simpleinventorysort", "inventorysorter",
    "inventory-profiles-next-api",

    # Атлантик-клиенты и визуалы
    "pulsevisuals", "topkavisuals", "customblockoverlay", "trajectoryguard",
    "viewmodel-changer", "viewmodelchanger", "viewmodel", "rainvisuals",
    "doabarrelroll", "moonlightclient", "soupapi", "soupvisuals", "soupbetter",
    "phantomvisuals", "mytheria", "kastrixvisuals", "rivalvisuals",
    "destravisuals", "reallyvisuals", "gammautils", "starkhelper", "stark_helper",
    "prizrakvisuals", "astrixvisuals", "adaptivevisuals", "feather", "lunar",
    "tapemouse", "autoclaninvest", "autotrade", "autotransfer", "topkaautodrop",
    "autodrop", "autoeat", "macrokeybinds", "rct", "primeparts", "chunksfadein",
    "antighost", "abstract", "customfov", "showyourself", "visualratio", "axolotlclient",
    "pearltrajectory", "wwaypoints"
}

ALLOWED_CLEAN = {re.sub(r"[-_\s]", "", m).lower() for m in ALLOWED_WHITELIST_RAW}

def extract_mod_metadata(jar: zipfile.ZipFile, filename: str):
    mod_id = ""
    mod_name = filename
    namelist = jar.namelist()

    # 1. Fabric
    if "fabric.mod.json" in namelist:
        try:
            data = json.loads(jar.read("fabric.mod.json").decode("utf-8", errors="ignore"))
            mod_id = str(data.get("id", "")).strip().lower()
            mod_name = str(data.get("name", mod_name)).strip()
            return mod_id, mod_name
        except Exception:
            pass

    # 2. Forge / NeoForge
    for manifest_path in ("META-INF/mods.toml", "META-INF/neoforge.mods.toml"):
        if manifest_path in namelist:
            try:
                toml_text = jar.read(manifest_path).decode("utf-8", errors="ignore")
                for line in toml_text.splitlines():
                    cleaned = line.strip()
                    if cleaned.startswith("modId="):
                        mod_id = cleaned.split("=", 1)[1].strip().strip('"\'').lower()
                    elif cleaned.startswith("displayName=") and mod_name == filename:
                        mod_name = cleaned.split("=", 1)[1].strip().strip('"\'')
                if mod_id:
                    return mod_id, mod_name
            except Exception:
                pass

    # 3. Quilt
    if "quilt.mod.json" in namelist:
        try:
            data = json.loads(jar.read("quilt.mod.json").decode("utf-8", errors="ignore"))
            qloader = data.get("quilt_loader", {})
            mod_id = str(qloader.get("id", "")).strip().lower()
            mod_name = str(qloader.get("metadata", {}).get("name", mod_name)).strip()
            return mod_id, mod_name
        except Exception:
            pass

    # 4. Legacy Forge mcmod.info
    if "mcmod.info" in namelist:
        try:
            info_data = json.loads(jar.read("mcmod.info").decode("utf-8", errors="ignore"))
            entry = info_data[0] if isinstance(info_data, list) and info_data else info_data.get("modList", [{}])[0]
            mod_id = str(entry.get("modid", "")).strip().lower()
            mod_name = str(entry.get("name", mod_name)).strip()
            return mod_id, mod_name
        except Exception:
            pass

    return mod_id, mod_name

def analyze_jar_sync(content: bytes, filename: str) -> dict:
    filename = (filename or "unknown.jar").strip() or "unknown.jar"
    sha256_hash = hashlib.sha256(content).hexdigest()
    file_size_kb = round(len(content) / 1024)

    try:
        with zipfile.ZipFile(BytesIO(content)) as jar:
            if len(jar.infolist()) > MAX_INNER_ENTRIES:
                return {
                    "filename": filename,
                    "status": Status.BANNED,
                    "name": filename,
                    "reason": "Архив содержит аномальное количество файлов (Zip-Bomb)",
                    "punishment": "Бан 28 дней",
                    "hash": sha256_hash
                }

            internal_paths = [name.lower() for name in jar.namelist()]
            mod_id, mod_name = extract_mod_metadata(jar, filename)

    except (zipfile.BadZipFile, OSError, ValueError):
        return {
            "filename": filename,
            "status": Status.BANNED,
            "name": filename,
            "reason": "Повреждённый или замаскированный .jar архив",
            "punishment": "Бан 28 дней",
            "hash": sha256_hash
        }

    raw_fn = filename.lower().replace(".jar", "")
    clean_fn = re.sub(r"[-_\s0-9\+\.]", "", raw_fn)
    clean_fn_stripped = re.sub(r"(fabric|forge|neoforge|quilt|mc.*)", "", clean_fn)
    clean_mod_id = re.sub(r"[-_\s]", "", mod_id)
    target_names = f"{filename} {mod_id} {mod_name}".lower()
    paths_str = " ".join(internal_paths)

    # 1. Глубокие сигнатуры
    for pattern, ban_name, duration, reason in DEEP_BANNED_COMPILED:
        if pattern.search(f"{mod_id} {paths_str}"):
            return {
                "filename": filename,
                "status": Status.BANNED,
                "name": ban_name,
                "reason": reason,
                "punishment": duration,
                "hash": sha256_hash
            }

    # 2. Проверка размеров (Luminar / Plintus Visuals)
    if "luminarvisuals" in clean_mod_id or "luminarvisuals" in clean_fn:
        if not (abs(file_size_kb - 7771) <= 30 or abs(file_size_kb - 4867) <= 30):
            return {
                "filename": filename,
                "status": Status.BANNED,
                "name": "Luminar Visuals",
                "reason": "Запрещённая версия Luminar Visuals (разрешены только 7 771 КБ и 4 867 КБ)",
                "punishment": "Бан 10 дней",
                "hash": sha256_hash
            }

    if "plintusvisuals" in clean_mod_id or "plintusvisuals" in clean_fn:
        if abs(file_size_kb - 61118) <= 50:
            return {
                "filename": filename,
                "status": Status.BANNED,
                "name": "Plintus Visuals 1.0.0",
                "reason": "Запрещённая версия Plintus Visuals (61 118 КБ)",
                "punishment": "Бан 10 дней",
                "hash": sha256_hash
            }

    # 3. Таргетированные запреты
    for pattern, ban_name, duration, reason in TARGETED_BANNED_COMPILED:
        if pattern.search(target_names):
            return {
                "filename": filename,
                "status": Status.BANNED,
                "name": ban_name,
                "reason": reason,
                "punishment": duration,
                "hash": sha256_hash
            }

    # 4. Белый список
    is_whitelisted = (
        (mod_id and (mod_id in ALLOWED_WHITELIST_RAW or clean_mod_id in ALLOWED_CLEAN)) or
        clean_fn in ALLOWED_CLEAN or
        clean_fn_stripped in ALLOWED_CLEAN or
        any(
            t in ALLOWED_CLEAN
            for token in re.split(r"[-_\s\.]+", raw_fn)
            if (t := re.sub(r"[0-9\+]", "", token)) and len(t) >= 3
        )
    )

    if is_whitelisted:
        return {
            "filename": filename,
            "status": Status.ALLOWED,
            "name": mod_name if mod_name != filename else filename,
            "reason": "Модификация проверена и входит в белый список разрешённых модов",
            "punishment": None,
            "hash": sha256_hash
        }

    # 5. Подозрительный / неизвестный
    return {
        "filename": filename,
        "status": Status.SUSPICIOUS,
        "name": mod_name if mod_name != filename else filename,
        "reason": "Мод отсутствует в базе. Создайте тикет в Discord для ручной проверки.",
        "punishment": "Требует одобрения",
        "hash": sha256_hash
    }

@app.post("/api/scan", response_model=List[ModScanResult])
async def scan_mods(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="Не переданы файлы для проверки")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=413, detail=f"Можно проверить не более {MAX_FILES} файлов")

    results = []
    total_size = 0

    for file in files:
        filename = (file.filename or "").strip()
        if not filename.lower().endswith(".jar"):
            continue

        content = await file.read(MAX_TOTAL_BYTES + 1)
        total_size += len(content)
        if total_size > MAX_TOTAL_BYTES:
            raise HTTPException(status_code=413, detail="Общий размер файлов не должен превышать 50 МБ")

        if not content:
            results.append({
                "filename": filename,
                "status": Status.BANNED,
                "name": filename,
                "reason": "Пустой файл не может быть проверен",
                "punishment": "Бан 28 дней",
                "hash": hashlib.sha256(content).hexdigest(),
            })
            continue

        analysis = await run_in_threadpool(analyze_jar_sync, content, filename)
        results.append(analysis)
        await file.close()

    if not results:
        raise HTTPException(status_code=400, detail="Поддерживаются только файлы с расширением .jar")

    return results
