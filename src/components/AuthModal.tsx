import { useState, type FormEvent } from 'react';
import { Lock, ShieldCheck, X } from 'lucide-react';
import { Language, UserRole } from '../types/infrastructure';

interface AuthSessionUser {
  userId: string;
  username: string;
  fullName: string;
  role: UserRole;
}

interface AuthModalProps {
  open: boolean;
  onClose: () => void;
  adminClaimed: boolean;
  lang: Language;
  onAuthenticated: (token: string, user: AuthSessionUser) => void;
}

export function AuthModal({
  open,
  onClose,
  adminClaimed,
  lang,
  onAuthenticated,
}: AuthModalProps) {
  const [username, setUsername] = useState('admin.medlabs');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!open) return null;

  const isClaimMode = !adminClaimed;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    if (isClaimMode) {
      if (password.length < 8) {
        setError(lang === 'ar' ? 'يجب أن تكون كلمة المرور 8 أحرف على الأقل.' : 'Password must be at least 8 characters.');
        return;
      }
      if (password !== confirmPassword) {
        setError(lang === 'ar' ? 'كلمتا المرور غير متطابقتين.' : 'Passwords do not match.');
        return;
      }
    }

    setLoading(true);
    try {
      const endpoint = isClaimMode ? '/api/auth/claim-admin' : '/api/auth/login';
      const body = isClaimMode ? { password } : { username, password };
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Authentication failed.');
      } else {
        onAuthenticated(data.token, data.user);
        setPassword('');
        setConfirmPassword('');
        onClose();
      }
    } catch {
      setError(lang === 'ar' ? 'تعذر الاتصال بالخادم.' : 'Unable to reach authentication server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl overflow-hidden">
        <div className="flex items-start justify-between gap-4 px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            {isClaimMode ? (
              <ShieldCheck className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            ) : (
              <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0" />
            )}
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                {isClaimMode
                  ? lang === 'ar'
                    ? 'تهيئة حساب المدير الأولي'
                    : 'Claim Initial Administrator Password'
                  : lang === 'ar'
                    ? 'تسجيل الدخول الآمن (RBAC)'
                    : 'Secure RBAC Sign In'}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {isClaimMode
                  ? lang === 'ar'
                    ? 'أنشئ كلمة مرور المدير ليتم تشفيرها على الخادم عبر scrypt.'
                    : 'Set the initial Administrator password (hashed server-side with scrypt).'
                  : lang === 'ar'
                    ? 'مصادقة مبنية على الأدوار لمنصة MedLabs.'
                    : 'Role-based authentication for MedLabs IT Operations.'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded-md cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 rounded-md text-rose-700 dark:text-rose-300">
              {error}
            </div>
          )}

          {isClaimMode ? (
            <div className="p-3 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded-md text-blue-900 dark:text-blue-200">
              {lang === 'ar' ? 'اسم المستخدم الإداري:' : 'Bootstrap Account:'}{' '}
              <span className="font-mono font-semibold">admin.medlabs</span>
            </div>
          ) : (
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {lang === 'ar' ? 'اسم المستخدم' : 'Username'}
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin.medlabs"
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-600"
                required
              />
            </div>
          )}

          <div>
            <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {lang === 'ar' ? 'كلمة المرور' : 'Password'}
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-600"
              required
            />
          </div>

          {isClaimMode && (
            <div>
              <label className="block font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {lang === 'ar' ? 'تأكيد كلمة المرور' : 'Confirm Password'}
              </label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3 py-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-600"
                required
              />
            </div>
          )}

          <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-slate-100 dark:border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 rounded-md cursor-pointer"
            >
              {lang === 'ar' ? 'إلغاء' : 'Cancel'}
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md disabled:opacity-60 cursor-pointer"
            >
              {loading
                ? lang === 'ar'
                  ? 'جاري التحقق...'
                  : 'Verifying...'
                : isClaimMode
                  ? lang === 'ar'
                    ? 'تعيين والدخول'
                    : 'Claim & Sign In'
                  : lang === 'ar'
                    ? 'دخول'
                    : 'Sign In'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
