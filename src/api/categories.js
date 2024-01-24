"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
const categories_1 = __importDefault(require("../categories"));
const events_1 = __importDefault(require("../events"));
const user_1 = __importDefault(require("../user"));
const groups_1 = __importDefault(require("../groups"));
const privileges_1 = __importDefault(require("../privileges"));
const categoriesAPI = {
    get: function (caller, data) {
        return __awaiter(this, void 0, void 0, function* () {
            const privCat = yield Promise.all([
                privileges_1.default.categories.get(data.cid, caller.uid),
                // The next line calls a function in a module that has not been updated to TS yet
                // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
                categories_1.default.getCategoryData(data.cid),
            ]);
            if (!privCat[1] || !privCat[0].read) {
                return null;
            }
            return privCat[1];
        });
    },
    create: function (caller, data) {
        return __awaiter(this, void 0, void 0, function* () {
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            const response = yield categories_1.default.create(data);
            const categoryObjs = yield categories_1.default.getCategories([response.cid], caller.uid);
            return categoryObjs[0];
        });
    },
    update: function (caller, data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!data) {
                throw new Error('[[error:invalid-data]]');
            }
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            yield categories_1.default.update(data);
        });
    },
    delete: function (caller, data) {
        return __awaiter(this, void 0, void 0, function* () {
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            const name = yield categories_1.default.getCategoryField(data.cid, 'name');
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            yield categories_1.default.purge(data.cid, caller.uid);
            yield events_1.default.log({
                type: 'category-purge',
                uid: caller.uid,
                ip: caller.ip,
                cid: data.cid,
                name: name,
            });
        });
    },
    getPrivileges: (caller, cid) => __awaiter(void 0, void 0, void 0, function* () {
        let responsePayload;
        if (cid === 'admin') {
            responsePayload = yield privileges_1.default.admin.list(caller.uid);
        }
        else if (!parseInt(cid, 10)) {
            responsePayload = yield privileges_1.default.global.list();
        }
        else {
            responsePayload = yield privileges_1.default.categories.list(cid);
        }
        return responsePayload;
    }),
    setPrivilege: (caller, data) => __awaiter(void 0, void 0, void 0, function* () {
        const existsCheck = yield Promise.all([
            user_1.default.exists(data.member),
            groups_1.default.exists(data.member),
        ]);
        if (!existsCheck[0] && !existsCheck[1]) {
            throw new Error('[[error:no-user-or-group]]');
        }
        const privs = Array.isArray(data.privilege) ? data.privilege : [data.privilege];
        const type = data.set ? 'give' : 'rescind';
        if (!privs.length) {
            throw new Error('[[error:invalid-data]]');
        }
        if (parseInt(data.cid, 10) === 0) {
            const adminPrivList = yield privileges_1.default.admin.getPrivilegeList();
            const adminPrivs = privs.filter(priv => adminPrivList.includes(priv));
            if (adminPrivs.length) {
                yield privileges_1.default.admin[type](adminPrivs, data.member);
            }
            const globalPrivList = yield privileges_1.default.global.getPrivilegeList();
            const globalPrivs = privs.filter(priv => globalPrivList.includes(priv));
            if (globalPrivs.length) {
                yield privileges_1.default.global[type](globalPrivs, data.member);
            }
        }
        else {
            const categoryPrivList = yield privileges_1.default.categories.getPrivilegeList();
            const categoryPrivs = privs.filter(priv => categoryPrivList.includes(priv));
            yield privileges_1.default.categories[type](categoryPrivs, data.cid, data.member);
        }
        yield events_1.default.log({
            uid: caller.uid,
            type: 'privilege-change',
            ip: caller.ip,
            privilege: data.privilege.toString(),
            cid: data.cid,
            action: data.set ? 'grant' : 'rescind',
            target: data.member,
        });
    }),
};
module.exports = categoriesAPI;
