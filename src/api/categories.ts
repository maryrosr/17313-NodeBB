import categories from '../categories';
import events from '../events';
import user from '../user';
import groups from '../groups';
import privileges from '../privileges';

type callerType ={
    uid: number;
    ip : number;
}

type dataType ={
    cid : string;
    privilege : string[];
    member : string;
    set : string;
}
type userPrivType ={
    read: boolean;
}
type responseType ={
    cid:string;
}
interface objCategoriesAPI {
    get(caller : callerType, data: dataType): Promise<unknown>;
    create(caller : callerType, data: dataType): Promise<unknown>;
    update(caller : callerType, data : dataType) : Promise<unknown>;
    delete(caller : callerType, data : dataType) : Promise<unknown>;
    getPrivileges(caller : callerType, cid : string) : Promise<unknown>;
    setPrivilege(caller : callerType, data : dataType) : Promise<unknown>;
}
interface privType {
    includes(priv :string): Promise<unknown>;
}
export = function (categoriesAPI : objCategoriesAPI) {
    categoriesAPI.get = async function (caller, data) {
        const privCat: [userPrivType, boolean] = await Promise.all([
            privileges.categories.get(data.cid, caller.uid),
            // The next line calls a function in a module that has not been updated to TS yet
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            categories.getCategoryData(data.cid),
        ]) as [userPrivType, boolean];
        if (!privCat[1] || !privCat[0].read) {
            return null;
        }

        return privCat[1];
    };

    categoriesAPI.create = async function (caller, data) {
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const response:responseType = await categories.create(data) as responseType;
        const categoryObjs:number[] = await categories.getCategories([response.cid], caller.uid) as number[];
        return categoryObjs[0];
    };

    categoriesAPI.update = async function (caller, data) {
        if (!data) {
            throw new Error('[[error:invalid-data]]');
        }
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await categories.update(data);
    };

    categoriesAPI.delete = async function (caller, data) {
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const name:string = await categories.getCategoryField(data.cid, 'name') as string;
        // The next line calls a function in a module that has not been updated to TS yet
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await categories.purge(data.cid, caller.uid);
        await events.log({
            type: 'category-purge',
            uid: caller.uid,
            ip: caller.ip,
            cid: data.cid,
            name: name,
        });
    };

    categoriesAPI.getPrivileges = async (caller, cid) => {
        let responsePayload :string;

        if (cid === 'admin') {
            responsePayload = await privileges.admin.list(caller.uid);
        } else if (!parseInt(cid, 10)) {
            responsePayload = await privileges.global.list();
        } else {
            responsePayload = await privileges.categories.list(cid);
        }

        return responsePayload;
    };

    categoriesAPI.setPrivilege = async (caller, data) => {
        const existsCheck:[boolean, boolean] = await Promise.all([
            user.exists(data.member),
            groups.exists(data.member),
        ]) as [boolean, boolean];

        if (!existsCheck[0] && !existsCheck[1]) {
            throw new Error('[[error:no-user-or-group]]');
        }
        const privs = Array.isArray(data.privilege) ? data.privilege : [data.privilege];
        const type = data.set ? 'give' : 'rescind';
        if (!privs.length) {
            throw new Error('[[error:invalid-data]]');
        }
        if (parseInt(data.cid, 10) === 0) {
            const adminPrivList :privType = await privileges.admin.getPrivilegeList() as privType;
            const adminPrivs = privs.filter(priv => adminPrivList.includes(priv));
            if (adminPrivs.length) {
                await privileges.admin[type](adminPrivs, data.member);
            }
            const globalPrivList :privType = await privileges.global.getPrivilegeList() as privType;
            const globalPrivs = privs.filter(priv => globalPrivList.includes(priv));
            if (globalPrivs.length) {
                await privileges.global[type](globalPrivs, data.member);
            }
        } else {
            const categoryPrivList:privType = await privileges.categories.getPrivilegeList() as privType;
            const categoryPrivs = privs.filter(priv => categoryPrivList.includes(priv));
            await privileges.categories[type](categoryPrivs, data.cid, data.member);
        }

        await events.log({
            uid: caller.uid,
            type: 'privilege-change',
            ip: caller.ip,
            privilege: data.privilege.toString(),
            cid: data.cid,
            action: data.set ? 'grant' : 'rescind',
            target: data.member,
        });
    };
}
